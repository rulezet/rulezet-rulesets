rule HKTL_NET_GUID_SharpStat {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Raikia/SharpStat"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "649c6cc0-e43b-558c-9567-00f352af528b"
    strings:
        $typelibguid0lo = "ffc5c721-49c8-448d-8ff4-2e3a7b7cc383" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}