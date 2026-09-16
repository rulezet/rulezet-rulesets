rule HKTL_NET_GUID_WireTap {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/djhohnstein/WireTap"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-22"
        modified = "2025-08-15"
        id = "5513a295-8907-5a9c-adca-760b33004229"
    strings:
        $typelibguid0lo = "b5067468-f656-450a-b29c-1c84cfe8dde5" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}