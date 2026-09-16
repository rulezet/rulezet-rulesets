rule HKTL_NET_GUID_KrbRelay {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/cube0x0/KrbRelay"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2022-11-21"
        modified = "2025-08-15"
        id = "3f59986c-8bd8-5e70-b3eb-038247d1ccd7"
    strings:
        $typelibguid0lo = "ed839154-90d8-49db-8cdd-972d1a6b2cfd" ascii wide
        $typelibguid1lo = "3b47eebc-0d33-4e0b-bab5-782d2d3680af" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}