rule HKTL_NET_NAME_RdpThief {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/0x09AL/RdpThief"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
        id = "5ad4feec-50db-5ebb-a609-9196e72a24aa"
    strings:
        $name = "RdpThief" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}