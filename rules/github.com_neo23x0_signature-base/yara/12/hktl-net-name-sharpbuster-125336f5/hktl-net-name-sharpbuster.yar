rule HKTL_NET_NAME_SharpBuster {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/passthehashbrowns/SharpBuster"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
        id = "d30c8ee5-88b9-53b5-b209-51f6f3b988cf"
    strings:
        $name = "SharpBuster" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}