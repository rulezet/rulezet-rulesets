rule HKTL_NET_NAME_HexyRunner {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/bao7uo/HexyRunner"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
        id = "67741b4d-7336-5c88-8f2c-e48c10b187b9"
    strings:
        $name = "HexyRunner" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}