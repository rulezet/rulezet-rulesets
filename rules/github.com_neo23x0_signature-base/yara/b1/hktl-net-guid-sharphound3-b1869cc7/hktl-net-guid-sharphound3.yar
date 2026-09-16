rule HKTL_NET_GUID_SharpHound3 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/BloodHoundAD/SharpHound3"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-29"
        modified = "2025-08-15"
        id = "58001912-88a1-527d-9d3e-d7c376a1fce4"
    strings:
        $typelibguid0lo = "a517a8de-5834-411d-abda-2d0e1766539c" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}