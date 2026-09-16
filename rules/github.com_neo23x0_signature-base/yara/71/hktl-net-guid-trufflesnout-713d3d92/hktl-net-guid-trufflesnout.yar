rule HKTL_NET_GUID_TruffleSnout {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/dsnezhkov/TruffleSnout"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "8135d39e-6a9e-567d-840f-8d8c6338cce1"
    strings:
        $typelibguid0lo = "33842d77-bce3-4ee8-9ee2-9769898bb429" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}