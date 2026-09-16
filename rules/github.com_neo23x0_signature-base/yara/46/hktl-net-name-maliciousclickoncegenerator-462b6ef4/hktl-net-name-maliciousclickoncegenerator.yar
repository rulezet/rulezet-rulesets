rule HKTL_NET_NAME_MaliciousClickOnceGenerator {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/Mr-Un1k0d3r/MaliciousClickOnceGenerator"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
        id = "683af3b4-4c91-5ff3-96bf-d5c1d9c19cc2"
    strings:
        $name = "MaliciousClickOnceGenerator" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}