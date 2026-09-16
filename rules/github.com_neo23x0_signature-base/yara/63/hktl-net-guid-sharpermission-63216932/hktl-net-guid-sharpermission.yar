rule HKTL_NET_GUID_SharPermission {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/mitchmoser/SharPermission"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2025-08-15"
        id = "d5027f51-f3ca-53cd-96d7-c355b5c2e6fa"
    strings:
        $typelibguid0lo = "84d2b661-3267-49c8-9f51-8f72f21aea47" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}