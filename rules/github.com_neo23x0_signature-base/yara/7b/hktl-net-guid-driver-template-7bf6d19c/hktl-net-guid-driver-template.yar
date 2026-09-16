rule HKTL_NET_GUID_Driver_Template {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/FuzzySecurity/Driver-Template"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2025-08-15"
        id = "539f88c5-e779-55e0-98df-299a9068de9b"
    strings:
        $typelibguid0lo = "bdb79ad6-639f-4dc2-8b8a-cd9107da3d69" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}