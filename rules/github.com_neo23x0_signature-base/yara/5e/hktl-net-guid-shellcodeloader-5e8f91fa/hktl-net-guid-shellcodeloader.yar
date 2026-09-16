rule HKTL_NET_GUID_ShellcodeLoader {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Hzllaga/ShellcodeLoader"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "b8787dac-48a3-5711-86ba-0fda86b6224e"
    strings:
        $typelibguid0lo = "a48fe0e1-30de-46a6-985a-3f2de3c8ac96" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}