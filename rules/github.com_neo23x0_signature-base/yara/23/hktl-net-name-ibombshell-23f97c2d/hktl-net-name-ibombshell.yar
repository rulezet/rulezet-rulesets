rule HKTL_NET_NAME_ibombshell {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/Telefonica/ibombshell"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
        id = "02f3272f-8e75-5df4-9052-a315ae202050"
    strings:
        $name = "ibombshell" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}