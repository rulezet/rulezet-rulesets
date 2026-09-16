rule HKTL_NET_NAME_Ghostpack_CompiledBinaries {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
        id = "7cc81894-8c01-5a17-a7ed-1cb4cf1e2d53"
    strings:
        $name = "Ghostpack-CompiledBinaries" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}