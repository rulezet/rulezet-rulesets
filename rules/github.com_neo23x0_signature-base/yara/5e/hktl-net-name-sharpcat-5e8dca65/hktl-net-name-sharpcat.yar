rule HKTL_NET_NAME_SharpCat {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/Cn33liz/SharpCat"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
        id = "a46be8d3-bf7b-5d86-b88b-33e6c8c152d8"
    strings:
        $name = "SharpCat" ascii wide fullword
        $compile = "AssemblyTitle" ascii wide fullword
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}