rule HKTL_NET_GUID_StandIn {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/FuzzySecurity/StandIn"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-21"
        modified = "2025-08-15"
        id = "2af3c28a-ce5d-5dea-9abe-ff54b180049e"
    strings:
        $typelibguid0lo = "01c142ba-7af1-48d6-b185-81147a2f7db7" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}