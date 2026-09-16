rule HKTL_NET_NAME_metasploit_sharp {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/VolatileMindsLLC/metasploit-sharp"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
        id = "b425f241-4887-5368-b42b-3fbbd3b769c6"
    strings:
        $name = "metasploit-sharp" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}