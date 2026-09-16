rule HKTL_NET_NAME_NativePayload_ARP {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/DamonMohammadbagher/NativePayload_ARP"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
        id = "9fac11f8-4e40-5cbc-a990-2ae48df20828"
    strings:
        $name = "NativePayload_ARP" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}