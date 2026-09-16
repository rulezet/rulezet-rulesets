rule HKTL_NET_NAME_RunasCs {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/antonioCoco/RunasCs"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
        id = "c5fc5b01-1d30-5af5-be99-e629cb23295b"
    strings:
        $name = "RunasCs" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}