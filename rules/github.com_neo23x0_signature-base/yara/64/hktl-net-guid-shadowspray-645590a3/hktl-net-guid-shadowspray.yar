rule HKTL_NET_GUID_ShadowSpray {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/Dec0ne/ShadowSpray"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-22"
        modified = "2025-08-15"
        id = "91dd52ef-07a1-5ffd-b5c3-59bca18d4c7c"
    strings:
        $typelibguid0lo = "7e47d586-ddc6-4382-848c-5cf0798084e1" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}