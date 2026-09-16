rule HKTL_NET_GUID_Nuages {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/p3nt4/Nuages"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-29"
        modified = "2025-08-15"
        id = "5ad947e2-bd71-50d4-9bbf-4d018c7ff36a"
    strings:
        $typelibguid0lo = "e9e80ac7-4c13-45bd-9bde-ca89aadf1294" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}