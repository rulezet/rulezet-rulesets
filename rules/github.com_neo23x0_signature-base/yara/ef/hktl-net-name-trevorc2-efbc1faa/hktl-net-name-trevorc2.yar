rule HKTL_NET_NAME_trevorc2 {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/trustedsec/trevorc2"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
        id = "d1634a0d-6964-5886-b836-85c3ce6b8a17"
    strings:
        $name = "trevorc2" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}