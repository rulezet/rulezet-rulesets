rule HKTL_NET_GUID_ExternalC2 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/ryhanson/ExternalC2"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "7266acbb-b10d-4873-9b99-12d2043b1d4e" ascii nocase wide
        $typelibguid1 = "5d9515d0-df67-40ed-a6b2-6619620ef0ef" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}