rule HKTL_NET_NAME_reconness {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/reconness/reconness"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
        id = "a30188e4-d96a-59d0-9f51-d7a7e07b14ba"
    strings:
        $name = "reconness" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}