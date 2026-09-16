rule HKTL_NET_GUID_SharpTask {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/jnqpblc/SharpTask"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "2cdd1a15-c70c-5eea-b5a7-8b4a445b9323"
    strings:
        $typelibguid0lo = "13e90a4d-bf7a-4d5a-9979-8b113e3166be" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}