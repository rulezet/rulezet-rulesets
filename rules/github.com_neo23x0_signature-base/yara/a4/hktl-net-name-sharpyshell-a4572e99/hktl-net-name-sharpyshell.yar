rule HKTL_NET_NAME_SharPyShell {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/antonioCoco/SharPyShell"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
        id = "3069c5eb-446e-5bfa-9df0-2e03f229d4d1"
    strings:
        $name = "SharPyShell" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}