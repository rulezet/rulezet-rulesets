rule HKTL_NET_GUID_The_Collection {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Tlgyt/The-Collection"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "4ae78576-ab75-5679-9a29-4d9a1ff03f15"
    strings:
        $typelibguid0lo = "579159ff-3a3d-46a7-b069-91204feb21cd" ascii wide
        $typelibguid1lo = "5b7dd9be-c8c3-4c4f-a353-fefb89baa7b3" ascii wide
        $typelibguid2lo = "43edcb1f-3098-4a23-a7f2-895d927bc661" ascii wide
        $typelibguid3lo = "5f19919d-cd51-4e77-973f-875678360a6f" ascii wide
        $typelibguid4lo = "17fbc926-e17e-4034-ba1b-fb2eb57f5dd3" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}