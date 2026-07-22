#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Generate ImsStack MCC-MNC policy overlays from the PhhIms carrier database."""

from __future__ import annotations

import argparse
import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path


FILE_PREFIX = "carrier_config_ext_mccmnc_"

TRANSPORT = {
    "udp": 0,
    "tcp": 1,
    "udp-preferred": 2,
    "tcp-preferred": 2,
    "tls": 3,
}
AUTH_ALGORITHMS = {
    "hmac-md5-96": 0,
    "hmac-sha-1-96": 1,
}
ENCRYPTION_ALGORITHMS = {
    "null": 0,
    "aes-cbc": 2,
}

ACCESS_NETWORK_TYPES = {
    "gsm": 1,
    "umts": 2,
    "hspa": 2,
    "lte": 3,
    "wifi": 5,
    "nr": 6,
}

POLICY_TRANSPORT = {
    "UDP": 0,
    "TCP": 1,
    "DYNAMIC": 2,
    "TLS": 3,
}


@dataclass(frozen=True)
class Mapping:
    index: int
    canonical_mccmnc: str
    source_plmn: str
    mno: str
    subset: str
    gid1: str
    gid2: str
    spn: str

    @property
    def specificity(self) -> int:
        return sum(bool(value) for value in (self.subset, self.gid1, self.gid2, self.spn))


def csv(value: str | None) -> list[str]:
    return [item.strip() for item in (value or "").split(",") if item.strip()]


def bool_value(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.lower() == "true"


def positive_int(value: str | None) -> int | None:
    try:
        result = int(value or "")
    except ValueError:
        return None
    return result if result > 0 else None


def add_bool(parent: ET.Element, name: str, value: bool) -> None:
    ET.SubElement(parent, "boolean", name=name, value=str(value).lower())


def add_int(parent: ET.Element, name: str, value: int | None) -> None:
    if value is not None:
        ET.SubElement(parent, "int", name=name, value=str(value))


def add_int_array(parent: ET.Element, name: str, values: list[int]) -> None:
    if not values:
        return
    array = ET.SubElement(parent, "int-array", name=name, num=str(len(values)))
    for value in values:
        ET.SubElement(array, "item", value=str(value))


def exact_regex(value: str) -> str:
    return re.escape(value)


def profile_for_mapping(mapping: Mapping, profiles: list[ET.Element]) -> ET.Element | None:
    base_mno = mapping.mno.split(":", 1)[0]
    candidates = [
        profile
        for profile in profiles
        if profile.get("mnoname", "").lower() == mapping.mno.lower()
    ]
    candidates += [
        profile
        for profile in profiles
        if profile.get("mnoname", "").lower() == base_mno.lower()
        and profile not in candidates
    ]
    for profile in candidates:
        if bool_value(profile.get("emergency_support")):
            continue
        if profile.get("pdn", "").lower() != "ims":
            continue
        if "mmtel" not in {service.lower() for service in csv(profile.get("services"))}:
            continue
        return profile
    return None


def switch_for_mapping(mapping: Mapping, switches: list[ET.Element]) -> ET.Element | None:
    exact = [
        switch for switch in switches
        if switch.get("mnoname", "").lower() == mapping.mno.lower()
    ]
    if exact:
        return exact[-1]
    base_mno = mapping.mno.split(":", 1)[0]
    base = [
        switch for switch in switches
        if switch.get("mnoname", "").lower() == base_mno.lower()
    ]
    return base[-1] if base else None


def fragment_filters(mapping: Mapping) -> dict[str, str]:
    filters: dict[str, str] = {}
    if mapping.subset and mapping.source_plmn.isdigit():
        filters["imsi"] = rf"^.{{{len(mapping.source_plmn)}}}{re.escape(mapping.subset)}.*$"
    if mapping.gid1:
        filters["gid1_prefix"] = mapping.gid1
    if mapping.gid2:
        filters["gid2_prefix"] = mapping.gid2
    if mapping.spn:
        filters["spn"] = exact_regex(mapping.spn)
    return filters


def populate_fragment(
    fragment: ET.Element,
    profile: ET.Element,
    service_switch: ET.Element | None,
) -> None:
    remote_uri_type = profile.get("remote_uri_type", "").lower()
    if remote_uri_type in {"tel", "sip"}:
        add_int(fragment, "ims.request_uri_type_int", 0 if remote_uri_type == "tel" else 1)

    transport = TRANSPORT.get(profile.get("transport", "").lower())
    add_int(fragment, "ims.sip_preferred_transport_int", transport)

    support_ipsec = bool_value(profile.get("support_ipsec"))
    add_bool(fragment, "ims.sip_over_ipsec_enabled_bool", support_ipsec)
    add_bool(fragment, "ims.sip_over_ipsec_enabled_in_roaming_bool", support_ipsec)

    auth = [
        AUTH_ALGORITHMS[item.lower()]
        for item in csv(profile.get("auth_algo"))
        if item.lower() in AUTH_ALGORITHMS
    ]
    encryption = [
        ENCRYPTION_ALGORITHMS[item.lower()]
        for item in csv(profile.get("enc_algo"))
        if item.lower() in ENCRYPTION_ALGORITHMS
    ]
    # Match PhhIms's conservative fallback and do not advertise 3DES, which its policy rejects.
    if not auth:
        auth = [1, 0]
    if not encryption:
        encryption = [0, 2]
    add_int_array(fragment, "ims.ipsec_authentication_algorithms_int_array", auth)
    add_int_array(fragment, "ims.ipsec_encryption_algorithms_int_array", encryption)

    services = {service.lower() for service in csv(profile.get("services"))}
    networks = {network.lower() for network in csv(profile.get("networks"))}
    rat_values = sorted({
        ACCESS_NETWORK_TYPES[network]
        for network in networks
        if network in ACCESS_NETWORK_TYPES
    })
    add_int_array(fragment, "ims.supported_rats_int_array", rat_values)

    def switch_value(name: str) -> bool | None:
        if service_switch is None or service_switch.get(name) is None:
            return None
        return bool_value(service_switch.get(name))

    def service_enabled(name: str, token: str) -> bool:
        configured = switch_value(name)
        return configured if configured is not None else not services or token in services

    def network_enabled(*names: str) -> bool:
        return not networks or any(name in networks for name in names)

    ims_enabled = switch_value("enableIms") is not False
    volte_enabled = (
        ims_enabled
        and network_enabled("lte", "nr")
        and service_enabled("enableServiceVolte", "mmtel")
    )
    vowifi_enabled = (
        ims_enabled
        and network_enabled("wifi")
        and service_enabled("enableServiceVowifi", "mmtel")
    )
    smsip_enabled = ims_enabled and service_enabled("enableServiceSmsip", "smsip")
    add_bool(fragment, "ims.carrier_policy_ims_enabled_bool", ims_enabled)
    add_bool(fragment, "ims.carrier_policy_volte_enabled_bool", volte_enabled)
    add_bool(fragment, "ims.carrier_policy_vowifi_enabled_bool", vowifi_enabled)
    add_bool(
        fragment,
        "ims.carrier_policy_sms_over_ims_enabled_bool",
        smsip_enabled,
    )
    add_int_array(
        fragment,
        "imssms.sms_over_ims_supported_rats_int_array",
        rat_values if smsip_enabled else [],
    )

    add_bool(
        fragment,
        "ims.registration_event_package_supported_bool",
        bool_value(profile.get("subscribe_for_reg"), default=True),
    )
    add_bool(
        fragment,
        "ims.gruu_enabled_bool",
        bool_value(profile.get("enable_gruu"), default=True),
    )
    add_int(
        fragment,
        "ims.registration_expiry_timer_sec_int",
        positive_int(profile.get("reg_expires")),
    )
    retry_base = positive_int(profile.get("reg_retry_base_time"))
    retry_max = positive_int(profile.get("reg_retry_max_time"))
    add_int(
        fragment,
        "ims.registration_retry_base_timer_millis_int",
        retry_base * 1000 if retry_base else None,
    )
    add_int(
        fragment,
        "ims.registration_retry_max_timer_millis_int",
        retry_max * 1000 if retry_max else None,
    )

    precondition = bool_value(profile.get("use_precondition"))
    add_bool(fragment, "ims.support_sdp_precondition_bool", precondition)
    add_bool(fragment, "imsvoice.voice_qos_precondition_supported_bool", precondition)
    add_bool(
        fragment,
        "imsvoice.voice_qos_precondition_supported_on_iwlan_bool",
        bool_value(profile.get("wifi_precondition_enabled")),
    )
    add_bool(
        fragment,
        "imsvoice.carrier_volte_roaming_available_bool",
        bool_value(profile.get("support_roaming")),
    )

    add_int(
        fragment,
        "imsvoice.session_expires_timer_sec_int",
        positive_int(profile.get("session_expires")),
    )
    add_int(
        fragment,
        "imsvoice.minimum_session_expires_timer_sec_int",
        positive_int(profile.get("min_se")),
    )
    ringing = positive_int(profile.get("ringing_timer"))
    ringback = positive_int(profile.get("ringback_timer"))
    add_int(
        fragment,
        "imsvoice.ringing_timer_millis_int",
        ringing * 1000 if ringing else None,
    )
    add_int(
        fragment,
        "imsvoice.ringback_timer_millis_int",
        ringback * 1000 if ringback else None,
    )

    mtu = positive_int(profile.get("mss_size"))
    if mtu is not None and 300 <= mtu <= 10000:
        add_int(fragment, "ims.max_allowed_network_mtu_int", mtu)
        add_int(fragment, "ims.ipv4_sip_mtu_size_cellular_int", mtu)
        add_int(fragment, "ims.ipv6_sip_mtu_size_cellular_int", mtu)

    keep_alive = positive_int(profile.get("keep_alive_interval"))
    if keep_alive and (
        profile.get("keep_alive_mode_mo", "none").lower() != "none"
        or profile.get("keep_alive_mode_mt", "none").lower() != "none"
    ):
        add_int(fragment, "imsvoice.send_udp_keep_alive_interval_time_millis_int", keep_alive)

    # Android 17 ImsMedia advertises EVS in policy but its encoder and decoder are TODO stubs.
    add_bool(fragment, "imsvoice.audio_evs_support_bool", False)


def read_policy(policy_file: Path | None) -> dict[str, ET.Element]:
    if policy_file is None:
        return {}
    policies: dict[str, ET.Element] = {}
    for carrier in ET.parse(policy_file).getroot().findall("carrier"):
        mccmnc = carrier.get("mccmnc", "")
        if len(mccmnc) == 6 and mccmnc.isdigit():
            policies[mccmnc] = carrier
    return policies


def policy_values(carrier: ET.Element) -> tuple[
    dict[str, bool], dict[str, int], dict[str, str], dict[str, list[str]]
]:
    booleans: dict[str, bool] = {}
    longs: dict[str, int] = {}
    strings: dict[str, str] = {}
    arrays: dict[str, list[str]] = {}
    for child in carrier:
        name = child.get("name", "")
        if child.tag == "boolean" and name:
            booleans[name] = bool_value(child.get("value"))
        elif child.tag == "long" and name:
            try:
                longs[name] = int(child.get("value", ""))
            except ValueError:
                pass
        elif child.tag == "string" and name:
            strings[name] = child.get("value", "")
        elif child.tag == "string-array" and name:
            arrays[name] = [item.get("value", "") for item in child.findall("item")]
    return booleans, longs, strings, arrays


def populate_policy_fragment(fragment: ET.Element, carrier: ET.Element) -> None:
    booleans, longs, strings, arrays = policy_values(carrier)

    if "subscribe_reg_event" in booleans:
        add_bool(fragment, "ims.registration_event_package_supported_bool",
                 booleans["subscribe_reg_event"])
    if "register_gruu_supported" in booleans:
        add_bool(fragment, "ims.gruu_enabled_bool", booleans["register_gruu_supported"])
    if "ipsec_supported" in booleans:
        add_bool(fragment, "ims.sip_over_ipsec_enabled_bool", booleans["ipsec_supported"])
        add_bool(fragment, "ims.sip_over_ipsec_enabled_in_roaming_bool",
                 booleans["ipsec_supported"])
    if "precondition_cellular" in booleans:
        add_bool(fragment, "ims.support_sdp_precondition_bool",
                 booleans["precondition_cellular"])
        add_bool(fragment, "imsvoice.voice_qos_precondition_supported_bool",
                 booleans["precondition_cellular"])
    if "roaming_supported" in booleans:
        add_bool(fragment, "imsvoice.carrier_volte_roaming_available_bool",
                 booleans["roaming_supported"])
    if "control_socket_udp" in booleans:
        add_int(fragment, "ims.sip_preferred_transport_int",
                0 if booleans["control_socket_udp"] else 1)

    transport = POLICY_TRANSPORT.get(strings.get("transport_policy", "").upper())
    add_int(fragment, "ims.sip_preferred_transport_int", transport)
    uri_type = strings.get("outgoing_target_uri_type", "").upper()
    if uri_type:
        add_int(fragment, "ims.request_uri_type_int", 0 if uri_type == "TEL" else 1)
    if strings.get("outgoing_invite_shape", "").upper() == "SINGTEL_COMPACT_STOCK":
        # This enables RFC compact header names. Singtel's narrower header whitelist still needs
        # packet-trace validation before adding a native formatter policy.
        add_bool(fragment, "ims.sip_compact_form_enabled_bool", True)

    direct_ints = {
        "registration_retry_base_ms": "ims.registration_retry_base_timer_millis_int",
        "registration_retry_max_ms": "ims.registration_retry_max_timer_millis_int",
        "registration_expires_seconds": "ims.registration_expiry_timer_sec_int",
        "session_expires_seconds": "imsvoice.session_expires_timer_sec_int",
        "min_se_seconds": "imsvoice.minimum_session_expires_timer_sec_int",
        "ringing_timeout_ms": "imsvoice.ringing_timer_millis_int",
        "ringback_timeout_ms": "imsvoice.ringback_timer_millis_int",
    }
    for policy_name, config_name in direct_ints.items():
        if longs.get(policy_name, 0) > 0:
            add_int(fragment, config_name, longs[policy_name])

    mtu = longs.get("mss_size")
    if mtu is not None and 300 <= mtu <= 10000:
        add_int(fragment, "ims.max_allowed_network_mtu_int", mtu)
        add_int(fragment, "ims.ipv4_sip_mtu_size_cellular_int", mtu)
        add_int(fragment, "ims.ipv6_sip_mtu_size_cellular_int", mtu)

    auth = [
        AUTH_ALGORITHMS[item.lower()]
        for item in arrays.get("security_client_algs", [])
        if item.lower() in AUTH_ALGORITHMS
    ]
    encryption = [
        ENCRYPTION_ALGORITHMS[item.lower()]
        for item in arrays.get("security_client_ealgs", [])
        if item.lower() in ENCRYPTION_ALGORITHMS
    ]
    add_int_array(fragment, "ims.ipsec_authentication_algorithms_int_array", auth)
    add_int_array(fragment, "ims.ipsec_encryption_algorithms_int_array", encryption)


def render_file(
    mccmnc: str,
    records: list[tuple[Mapping, ET.Element, ET.Element | None]],
    policy: ET.Element | None,
) -> bytes:
    root = ET.Element("carrier_config_list")
    for mapping, profile, service_switch in sorted(records, key=lambda record: (
        record[0].specificity, record[0].index
    )):
        root.append(ET.Comment(
            f" PhhIms mapping {mapping.mno}; profile {profile.get('name', '')} "
        ))
        fragment = ET.SubElement(root, "carrier_config", fragment_filters(mapping))
        populate_fragment(fragment, profile, service_switch)

    if policy is not None:
        root.append(ET.Comment(
            f" PhhIms reviewed policy {policy.get('name', mccmnc)} "
        ))
        fragment = ET.SubElement(root, "carrier_config")
        populate_policy_fragment(fragment, policy)
        if len(fragment) == 0:
            root.remove(fragment)

    ET.indent(root, space="    ")
    body = ET.tostring(root, encoding="utf-8", xml_declaration=True)
    notice = (
        b"\n<!-- SPDX-License-Identifier: GPL-2.0-only -->\n"
        b"<!-- Generated from the PhhIms carrier database; do not edit by hand. -->\n"
    )
    return body.split(b"\n", 1)[0] + notice + body.split(b"\n", 1)[1] + b"\n"


def generate(source: Path, output: Path, policy_file: Path | None, check: bool) -> int:
    database = ET.parse(source).getroot()
    profiles_node = database.find("profiles")
    mappings_node = database.find("mappings")
    switches_node = database.find("switches")
    profiles = list(profiles_node) if profiles_node is not None else []
    switches = list(switches_node) if switches_node is not None else []
    policies = read_policy(policy_file)
    grouped: dict[str, list[tuple[Mapping, ET.Element, ET.Element | None]]] = defaultdict(list)
    skipped = 0

    for index, element in enumerate(mappings_node if mappings_node is not None else []):
        canonical = element.get("mccmnc", "")
        if len(canonical) != 6 or not canonical.isdigit():
            skipped += 1
            continue
        mapping = Mapping(
            index=index,
            canonical_mccmnc=canonical,
            source_plmn=element.get("plmn", ""),
            mno=element.get("mno", ""),
            subset=element.get("subset", ""),
            gid1=element.get("gid1", ""),
            gid2=element.get("gid2", ""),
            spn=element.get("spname", ""),
        )
        profile = profile_for_mapping(mapping, profiles)
        if profile is None:
            skipped += 1
            continue
        grouped[canonical].append((mapping, profile, switch_for_mapping(mapping, switches)))

    expected = {
        f"{FILE_PREFIX}{mccmnc}.xml": render_file(
            mccmnc, grouped.get(mccmnc, []), policies.get(mccmnc)
        )
        for mccmnc in grouped.keys() | policies.keys()
    }

    if check:
        mismatches = [
            name for name, content in expected.items()
            if not (output / name).is_file() or (output / name).read_bytes() != content
        ]
        extras = [path.name for path in output.glob(f"{FILE_PREFIX}*.xml") if path.name not in expected]
        if mismatches or extras:
            for name in sorted(mismatches + extras):
                print(name, file=sys.stderr)
            return 1
    else:
        output.mkdir(parents=True, exist_ok=True)
        for old_file in output.glob(f"{FILE_PREFIX}*.xml"):
            old_file.unlink()
        for name, content in sorted(expected.items()):
            (output / name).write_bytes(content)

    print(
        f"{len(expected)} files, {sum(len(value) for value in grouped.values())} mappings, "
        f"{skipped} mappings without a transferable MMTEL profile"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    return generate(args.source, args.output, args.policy, args.check)


if __name__ == "__main__":
    raise SystemExit(main())
