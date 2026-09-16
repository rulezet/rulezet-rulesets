rule HKTL_NET_GUID_ForgeCert {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/GhostPack/ForgeCert"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-18"
        modified = "2025-08-15"
        id = "06b3ffbb-5a76-50a0-86dc-b9658bf2d7ec"
    strings:
        $typelibguid0lo = "bd346689-8ee6-40b3-858b-4ed94f08d40a" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}