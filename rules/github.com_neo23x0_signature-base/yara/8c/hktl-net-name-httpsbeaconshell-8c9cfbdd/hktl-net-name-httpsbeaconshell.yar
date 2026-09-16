rule HKTL_NET_NAME_HTTPSBeaconShell {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/limbenjamin/HTTPSBeaconShell"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
        id = "3bd7234b-a23e-5818-aed1-52d42023943b"
    strings:
        $name = "HTTPSBeaconShell" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}