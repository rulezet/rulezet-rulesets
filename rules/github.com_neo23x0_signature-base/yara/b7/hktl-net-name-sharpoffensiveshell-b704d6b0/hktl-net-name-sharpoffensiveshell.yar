rule HKTL_NET_NAME_SharpOffensiveShell {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/darkr4y/SharpOffensiveShell"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
        id = "f223fb95-9f16-5504-a6ce-de9d75b38eaa"
    strings:
        $name = "SharpOffensiveShell" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}