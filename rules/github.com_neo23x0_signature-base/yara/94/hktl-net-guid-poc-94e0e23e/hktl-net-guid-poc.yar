rule HKTL_NET_GUID_PoC {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/thezdi/PoC"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-21"
        modified = "2025-08-15"
        id = "5669bc1a-b32e-5ae7-bf94-8ed2a124c765"
    strings:
        $typelibguid0lo = "89f9d411-e273-41bb-8711-209fd251ca88" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}