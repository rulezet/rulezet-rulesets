rule HKTL_NET_GUID_Sharpire {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0xbadjuju/Sharpire"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "32bdaa0f-3afc-5e0e-a20f-e21f33909af7"
    strings:
        $typelibguid0lo = "39b75120-07fe-4833-a02e-579ff8b68331" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}