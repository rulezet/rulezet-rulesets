rule HKTL_NET_NAME_AggressiveProxy {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/EncodeGroup/AggressiveProxy"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
        id = "e2d3c4e2-404b-59f8-b3d0-a7cef4dfd0ff"
    strings:
        $name = "AggressiveProxy" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}