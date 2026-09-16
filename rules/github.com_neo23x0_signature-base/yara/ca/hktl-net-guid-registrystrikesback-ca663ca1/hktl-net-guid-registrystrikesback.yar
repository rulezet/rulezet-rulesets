rule HKTL_NET_GUID_RegistryStrikesBack {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/mdsecactivebreach/RegistryStrikesBack"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2025-08-15"
        id = "1577ed24-0e17-54f9-bc29-bb209acf9645"
    strings:
        $typelibguid0lo = "90ebd469-d780-4431-9bd8-014b00057665" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}