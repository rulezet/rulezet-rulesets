rule HKTL_NET_GUID_ShellCodeRunner {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/antman1p/ShellCodeRunner"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "949364e7-dcb6-5afd-ade9-cc34a6e15e97"
    strings:
        $typelibguid0lo = "634874b7-bf85-400c-82f0-7f3b4659549a" ascii wide
        $typelibguid1lo = "2f9c3053-077f-45f2-b207-87c3c7b8f054" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}