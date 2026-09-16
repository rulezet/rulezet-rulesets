rule HKTL_NET_NAME_tvasion {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/loadenmb/tvasion"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
        id = "324cddc6-36d9-5670-827e-24e80dcc66a9"
    strings:
        $name = "tvasion" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}