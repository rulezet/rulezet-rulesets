rule HKTL_NET_NAME_PandaSniper {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/QAX-A-Team/PandaSniper"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
        id = "006400fb-7e6d-563b-ba78-17937983c9ba"
    strings:
        $name = "PandaSniper" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}