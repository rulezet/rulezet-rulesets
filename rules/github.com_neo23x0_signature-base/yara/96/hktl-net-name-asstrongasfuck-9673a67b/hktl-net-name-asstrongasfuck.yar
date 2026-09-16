rule HKTL_NET_NAME_AsStrongAsFuck {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/Charterino/AsStrongAsFuck"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
        id = "4c63c8a2-5889-5177-9f66-8e5f755025a3"
    strings:
        $name = "AsStrongAsFuck" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}