rule HKTL_NET_NAME_NativePayload_ReverseShell {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/DamonMohammadbagher/NativePayload_ReverseShell"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
        id = "eec77c09-02db-5d74-8526-e201d2fe6fc8"
    strings:
        $name = "NativePayload_ReverseShell" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}