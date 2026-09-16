rule HKTL_NET_GUID_hanzoInjection {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/P0cL4bs/hanzoInjection"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "c432bf68-49bf-57c7-bbfa-7bd2f3506c52"
    strings:
        $typelibguid0lo = "32e22e25-b033-4d98-a0b3-3d2c3850f06c" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}