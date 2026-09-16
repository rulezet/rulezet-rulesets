rule HKTL_NET_GUID_Lime_Crypter {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/Lime-Crypter"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "484c7a15-7ab2-57d3-848c-0fddff753d52"
    strings:
        $typelibguid0lo = "f93c99ed-28c9-48c5-bb90-dd98f18285a6" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}