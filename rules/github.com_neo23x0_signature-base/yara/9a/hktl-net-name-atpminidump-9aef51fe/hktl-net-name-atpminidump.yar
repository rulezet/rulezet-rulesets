rule HKTL_NET_NAME_ATPMiniDump {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/b4rtik/ATPMiniDump"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
        id = "97981569-fe94-5600-8319-946edb4265e7"
    strings:
        $name = "ATPMiniDump" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}