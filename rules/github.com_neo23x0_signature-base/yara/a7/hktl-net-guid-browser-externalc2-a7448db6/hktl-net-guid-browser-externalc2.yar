rule HKTL_NET_GUID_Browser_ExternalC2 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/mdsecactivebreach/Browser-ExternalC2"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "8c309522-90e7-5f5a-b456-3a472756d397"
    strings:
        $typelibguid0lo = "10a730cd-9517-42d5-b3e3-a2383515cca9" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}