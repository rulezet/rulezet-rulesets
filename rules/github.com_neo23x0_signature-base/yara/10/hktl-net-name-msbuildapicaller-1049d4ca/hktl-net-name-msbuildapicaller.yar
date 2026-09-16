rule HKTL_NET_NAME_MSBuildAPICaller {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/rvrsh3ll/MSBuildAPICaller"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
        id = "143da57f-b01f-5688-b741-1bc4d06cd7d1"
    strings:
        $name = "MSBuildAPICaller" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}