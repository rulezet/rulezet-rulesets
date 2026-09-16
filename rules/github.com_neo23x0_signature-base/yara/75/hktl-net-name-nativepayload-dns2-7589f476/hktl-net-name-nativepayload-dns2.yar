rule HKTL_NET_NAME_NativePayload_DNS2 {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/DamonMohammadbagher/NativePayload_DNS2"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
        id = "0fa01355-de57-573e-9056-0b7a5d24572d"
    strings:
        $name = "NativePayload_DNS2" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}