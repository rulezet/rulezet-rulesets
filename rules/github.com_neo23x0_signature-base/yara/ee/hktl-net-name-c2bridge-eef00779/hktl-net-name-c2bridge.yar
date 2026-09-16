rule HKTL_NET_NAME_C2Bridge {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/cobbr/C2Bridge"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
        id = "357051aa-61ea-5454-a996-b4e3a45ac865"
    strings:
        $name = "C2Bridge" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}