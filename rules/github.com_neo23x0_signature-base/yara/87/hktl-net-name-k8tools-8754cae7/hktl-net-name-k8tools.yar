rule HKTL_NET_NAME_K8tools {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/k8gege/K8tools"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
        id = "b30fc856-073d-542f-b222-a957322732c2"
    strings:
        $name = "K8tools" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}