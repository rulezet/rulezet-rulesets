rule HKTL_NET_GUID_Koh {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/GhostPack/Koh"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-18"
        modified = "2025-08-15"
        id = "9702526c-b10d-553d-a803-47e352533858"
    strings:
        $typelibguid0lo = "4d5350c8-7f8c-47cf-8cde-c752018af17e" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}