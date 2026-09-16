rule HKTL_NET_GUID_SharpHide {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/outflanknl/SharpHide"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2025-08-15"
        id = "928e00c1-549a-58f5-9e7e-982a4319691a"
    strings:
        $typelibguid0lo = "443d8cbf-899c-4c22-b4f6-b7ac202d4e37" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}