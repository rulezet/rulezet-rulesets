rule HKTL_NET_GUID_Carbuncle {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/checkymander/Carbuncle"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "4a87882e-570b-5b40-a8e3-47ebac01d257"
    strings:
        $typelibguid0lo = "3f239b73-88ae-413b-b8c8-c01a35a0d92e" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}