rule HKTL_NET_GUID_Group3r {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/Group3r/Group3r.git"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2022-11-21"
        modified = "2025-08-15"
        id = "0571d71e-50ca-5c1b-b750-34acc2d06687"
    strings:
        $typelibguid0lo = "868a6c76-c903-4a94-96fd-a2c6ba75691c" ascii wide
        $typelibguid1lo = "caa7ab97-f83b-432c-8f9c-c5f1530f59f7" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}