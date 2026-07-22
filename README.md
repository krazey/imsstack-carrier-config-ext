# ImsStack carrier configuration extension

This data-only Soong module supplies the optional
`imsstack-carrier-config-ext` library expected by AOSP ImsStack. It is
device-independent and can be shared by every product that builds the same
userspace IMS provider.

The committed assets contain:

- 384 carrier-ID and MCC-MNC profiles from the last public AOSP ImsStack
  carrier set before commit `0fa1e52eec0251bafd5a52411f5bb291b8cc4c58`
  removed them.
- 988 MCC-MNC extension files generated from 1,304 transferable mappings in
  the current PhhIms carrier database.

The AOSP profiles keep their Apache-2.0 notices. Files named
`carrier_config_ext_mccmnc_*.xml` are generated from the GPL-2.0-only PhhIms
data and carry that notice individually.

## Source snapshot

- PhhIms commit: `69ff68aad4e82fe56406b0893a7ebfe60d7debec`
- `sip_carrier_database.xml` SHA-256:
  `ab2b76ffe580f06283d93e223962de3181863d8ecdef0c8e5a0dcca30895993d`
- `sip_carrier_policies.xml` SHA-256:
  `f25173c329f6489ee90226397735e48d933cc504b1ae90355fc3d1d6310605bd`

## Build integration

Place this repository at `vendor/lineage/imsstack-carrier-config-ext` and add:

```make
PRODUCT_SOONG_NAMESPACES += \
    vendor/lineage/imsstack-carrier-config-ext

$(call soong_config_set_bool,imsstack_namespace,use_carrier_config_ext,true)
```

The matching ImsStack patch layers
`carrier_config_ext_mccmnc_<MCC><MNC>.xml` after the canonical carrier-ID
profile. IMSI, SPN, GID1-prefix, and GID2-prefix fragments remain data driven.
Service switches can disable VoLTE, VoWiFi, or SMS over IMS, but cannot enable
a service disabled by Android CarrierConfig.

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
only replaces `carrier_config_ext_mccmnc_*.xml`; it does not modify the AOSP
carrier-ID baseline.

Only fields with direct ImsStack equivalents are transferred. Carrier-specific
number rewriting, SIP header shaping, and CS fallback rules need separate,
trace-verified stack policy and are not guessed here.
