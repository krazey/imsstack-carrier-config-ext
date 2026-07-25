# ImsStack carrier configuration extension

This data-only Soong module supplies the optional
`imsstack-carrier-config-ext` library expected by AOSP ImsStack. It is
device-independent and can be shared by every product that builds the same
userspace IMS provider.

The committed assets contain:

- 384 carrier-ID and MCC-MNC profiles from the last public AOSP ImsStack
  carrier set before commit `0fa1e52eec0251bafd5a52411f5bb291b8cc4c58`
  removed them.
- 988 MCC-MNC compatibility files generated from 1,304 transferable mappings
  in the current PhhIms carrier database.
- A small, separate set of reviewed MCC-MNC overrides for trace-validated
  carrier exceptions.

The AOSP profiles keep their Apache-2.0 notices. Files named
`carrier_config_ext_mccmnc_*.xml` and
`carrier_config_override_mccmnc_*.xml` are generated from the GPL-2.0-only
PhhIms data and carry that notice individually.

## Source snapshot

- PhhIms commit: `a3fec01ebc4f51c39026565c4a451fef454637fa`
- `sip_carrier_database.xml` SHA-256:
  `ab2b76ffe580f06283d93e223962de3181863d8ecdef0c8e5a0dcca30895993d`
- `sip_carrier_policies.xml` SHA-256:
  `e64c0c1ae78f502a1ca8a71ea4d6ba09c1ccbd55631a4ce4eb46cc4990566407`

## Build integration

Place this repository at `vendor/lineage/imsstack-carrier-config-ext` and add:

```make
PRODUCT_SOONG_NAMESPACES += \
    vendor/lineage/imsstack-carrier-config-ext

$(call soong_config_set_bool,imsstack_namespace,use_carrier_config_ext,true)
```

The matching ImsStack patch layers
`carrier_config_ext_mccmnc_<MCC><MNC>.xml` as compatibility defaults before
Android CarrierConfig. Reviewed
`carrier_config_override_mccmnc_<MCC><MNC>.xml` exceptions are applied after
Android CarrierConfig. IMSI, SPN, GID1-prefix, and GID2-prefix fragments remain
data driven. Service switches can disable VoLTE, VoWiFi, or SMS over IMS, but
cannot enable a service disabled by Android CarrierConfig.

Reviewed policies may also declare an explicit MNO alias. This preserves
PhhIms realm-selected behavior for SingTel mappings `525001`, `525002`, and
`525096` without adding carrier-name checks to ImsStack.

## Refreshing from PhhIms

Generated files are committed; normal product builds do not need PhhIms or
Python. To refresh them after a PhhIms database update:

```sh
tools/generate_from_phhims.py \
    /path/to/PhhIms/app/src/main/res/xml/sip_carrier_database.xml \
    assets/carrier_config \
    --policy /path/to/PhhIms/app/src/main/res/xml/sip_carrier_policies.xml
```

Use the same command with `--check` to verify reproducibility. The generator
replaces both generated MCC-MNC namespaces; it does not modify the AOSP
carrier-ID baseline.

Only fields with direct ImsStack equivalents are transferred. Reviewed policy
translation is explicit in the generator; unsupported carrier behavior is
omitted instead of being guessed.
