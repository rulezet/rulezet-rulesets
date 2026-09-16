rule HKTL_NET_GUID_XORedReflectiveDLL {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/r3nhat/XORedReflectiveDLL"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "9b584bfb-98ef-50ee-b546-780c4b210a1b"
    strings:
        $typelibguid0lo = "c0e49392-04e3-4abb-b931-5202e0eb4c73" ascii wide
        $typelibguid1lo = "30eef7d6-cee8-490b-829f-082041bc3141" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}