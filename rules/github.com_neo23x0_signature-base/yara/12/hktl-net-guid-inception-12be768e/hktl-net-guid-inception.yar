rule HKTL_NET_GUID_Inception {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/two06/Inception"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "8d18f1d5-9c9a-5258-9f96-fa24b702c6ad"
    strings:
        $typelibguid0lo = "03d96b8c-efd1-44a9-8db2-0b74db5d247a" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}