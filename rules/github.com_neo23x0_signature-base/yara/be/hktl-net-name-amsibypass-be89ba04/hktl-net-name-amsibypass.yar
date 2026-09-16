rule HKTL_NET_NAME_AmsiBypass {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/0xB455/AmsiBypass"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash = "8fa4ba512b34a898c4564a8eac254b6a786d195b"
        author = "Arnim Rupp"
        date = "2021-01-22"
        modified = "2024-12-10"
        id = "26db14d8-1034-5bd1-a719-4756c832901d"
    strings:
        $s_name = "AmsiBypass" ascii wide
        $s_compile = "AssemblyTitle" ascii wide

        $fp1 = "Adaptive Threat Protection" wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of ($s*)
        and not 1 of ($fp*)
}