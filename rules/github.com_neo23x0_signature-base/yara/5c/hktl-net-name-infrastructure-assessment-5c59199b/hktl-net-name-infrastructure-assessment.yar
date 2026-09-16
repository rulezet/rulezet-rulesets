rule HKTL_NET_NAME_Infrastructure_Assessment {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/NyaMeeEain/Infrastructure-Assessment"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
        id = "efacc12b-92b3-5b22-b5bb-cd5a7d7eea0e"
    strings:
        $name = "Infrastructure-Assessment" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}