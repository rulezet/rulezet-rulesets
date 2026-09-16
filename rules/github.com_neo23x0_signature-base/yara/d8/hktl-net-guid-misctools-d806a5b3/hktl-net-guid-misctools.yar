rule HKTL_NET_GUID_MiscTools {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rasta-mouse/MiscTools"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "ce49cc7b-a5a5-52b7-a7bf-bbb0c5b29b8a"
    strings:
        $typelibguid0lo = "384e9647-28a9-4835-8fa7-2472b1acedc0" ascii wide
        $typelibguid1lo = "d7ec0ef5-157c-4533-bbcd-0fe070fbf8d9" ascii wide
        $typelibguid2lo = "10085d98-48b9-42a8-b15b-cb27a243761b" ascii wide
        $typelibguid3lo = "6aacd159-f4e7-4632-bad1-2ae8526a9633" ascii wide
        $typelibguid4lo = "49a6719e-11a8-46e6-ad7a-1db1be9fea37" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}