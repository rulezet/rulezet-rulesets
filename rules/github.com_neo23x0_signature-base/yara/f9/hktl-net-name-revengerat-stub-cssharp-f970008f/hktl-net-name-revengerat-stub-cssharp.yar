rule HKTL_NET_NAME_RevengeRAT_Stub_CSsharp {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/NYAN-x-CAT/RevengeRAT-Stub-CSsharp"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
        id = "06dce4f9-4d7a-5976-a87a-07c539e5dbe8"
    strings:
        $name = "RevengeRAT-Stub-CSsharp" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}