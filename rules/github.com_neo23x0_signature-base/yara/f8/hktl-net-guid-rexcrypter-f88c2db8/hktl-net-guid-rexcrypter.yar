rule HKTL_NET_GUID_RexCrypter {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/syrex1013/RexCrypter"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "5ebbeab3-3e93-5544-8f74-3d1b47335d8b"
    strings:
        $typelibguid0lo = "10cd7c1c-e56d-4b1b-80dc-e4c496c5fec5" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}