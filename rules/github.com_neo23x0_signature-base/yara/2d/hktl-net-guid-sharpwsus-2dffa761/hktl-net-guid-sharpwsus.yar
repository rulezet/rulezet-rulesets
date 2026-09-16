rule HKTL_NET_GUID_SharpWSUS {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/nettitude/SharpWSUS"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-22"
        modified = "2025-08-15"
        id = "f020eea9-4ff4-5242-b9b2-53284505dab4"
    strings:
        $typelibguid0lo = "42cabb74-1199-40f1-9354-6294bba8d3a4" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}