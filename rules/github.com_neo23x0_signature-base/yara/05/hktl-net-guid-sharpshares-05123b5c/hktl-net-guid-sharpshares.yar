rule HKTL_NET_GUID_SharpShares {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/djhohnstein/SharpShares/"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "e96aa79b-1da2-5b0c-9ac2-b6e201e06ec6"
    strings:
        $typelibguid0lo = "fe9fdde5-3f38-4f14-8c64-c3328c215cf2" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}