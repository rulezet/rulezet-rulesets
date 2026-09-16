rule HKTL_NET_GUID_SharpChisel {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/shantanu561993/SharpChisel"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2025-08-15"
        id = "3b7e6703-ebe8-5a98-839f-7d0349ab483f"
    strings:
        $typelibguid0lo = "f5f21e2d-eb7e-4146-a7e1-371fd08d6762" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}