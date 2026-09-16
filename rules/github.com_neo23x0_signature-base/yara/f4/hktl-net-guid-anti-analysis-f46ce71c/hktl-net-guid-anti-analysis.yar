rule HKTL_NET_GUID_Anti_Analysis {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/Anti-Analysis"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "bd527841-065e-57e9-b70e-c9d232072f1b"
    strings:
        $typelibguid0lo = "3092c8df-e9e4-4b75-b78e-f81a0058a635" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}