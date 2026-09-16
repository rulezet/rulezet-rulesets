rule HKTL_NET_NAME_GhostLoader {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/TheWover/GhostLoader"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
        id = "d8d88f3f-f250-55ff-88a6-4623e12ef89d"
    strings:
        $name = "GhostLoader" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}