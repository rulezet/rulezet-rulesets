rule HKTL_NET_GUID_SharpPrinter {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rvrsh3ll/SharpPrinter"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "10270351-ad80-5330-971b-bc8f635f05f4"
    strings:
        $typelibguid0lo = "41b2d1e5-4c5d-444c-aa47-629955401ed9" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}