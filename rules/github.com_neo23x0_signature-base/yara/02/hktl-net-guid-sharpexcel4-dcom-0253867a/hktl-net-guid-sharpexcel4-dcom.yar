rule HKTL_NET_GUID_SharpExcel4_DCOM {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rvrsh3ll/SharpExcel4-DCOM"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "12d3f26b-40ca-5034-a7c2-9be9c8a7599b"
    strings:
        $typelibguid0lo = "68b83ce5-bbd9-4ee3-b1cc-5e9223fab52b" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}