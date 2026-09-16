rule HKTL_NET_NAME_StageStrike {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/RedXRanger/StageStrike"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
        id = "e3f9de04-87f6-5b07-b5b0-a26167937fcc"
    strings:
        $name = "StageStrike" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}