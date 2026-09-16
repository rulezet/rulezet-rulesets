rule HKTL_NET_GUID_LimeUSB_Csharp {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/LimeUSB-Csharp"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "dfa96b36-e84c-510b-b16b-bd686777b83d"
    strings:
        $typelibguid0lo = "94ea43ab-7878-4048-a64e-2b21b3b4366d" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}