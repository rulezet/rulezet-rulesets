rule HKTL_NET_NAME_shellcodeTester {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/tophertimzen/shellcodeTester"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
        id = "964093a4-e6d7-51b7-928a-b1cd40dc11cc"
    strings:
        $name = "shellcodeTester" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}