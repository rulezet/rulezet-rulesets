rule HKTL_NET_GUID_UAC_Escaper {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/UAC-Escaper"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "ea95ff3c-0cbb-5230-b5e4-bd8b2ff975eb"
    strings:
        $typelibguid0lo = "95359279-5cfa-46f6-b400-e80542a7336a" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}