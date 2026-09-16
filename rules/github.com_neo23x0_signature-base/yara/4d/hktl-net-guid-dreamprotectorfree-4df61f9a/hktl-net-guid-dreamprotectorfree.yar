rule HKTL_NET_GUID_DreamProtectorFree {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Paskowsky/DreamProtectorFree"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "9ebee989-3441-5a76-b243-08de978b541c"
    strings:
        $typelibguid0lo = "f7e8a902-2378-426a-bfa5-6b14c4b40aa3" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}