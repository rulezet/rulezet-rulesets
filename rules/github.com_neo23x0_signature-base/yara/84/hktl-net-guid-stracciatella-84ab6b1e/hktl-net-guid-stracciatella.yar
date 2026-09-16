rule HKTL_NET_GUID_Stracciatella {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/mgeeky/Stracciatella"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "5b1a8102-6d59-5f2f-8ae2-b3c1f75a561d"
    strings:
        $typelibguid0lo = "eaafa0ac-e464-4fc4-9713-48aa9a6716fb" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}