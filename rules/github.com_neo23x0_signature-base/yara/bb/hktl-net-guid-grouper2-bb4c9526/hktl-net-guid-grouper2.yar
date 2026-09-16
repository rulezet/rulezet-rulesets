rule HKTL_NET_GUID_Grouper2 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/l0ss/Grouper2/"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "a9cd9a16-b2a5-5d15-af89-7a8d0f1835bb"
    strings:
        $typelibguid0lo = "5decaea3-2610-4065-99dc-65b9b4ba6ccd" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}