rule HKTL_NET_GUID_WhiteListEvasion {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/khr0x40sh/WhiteListEvasion"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "cd2740d0-0315-5a32-b34a-1998024fcc06"
    strings:
        $typelibguid0lo = "858386df-4656-4a1e-94b7-47f6aa555658" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}