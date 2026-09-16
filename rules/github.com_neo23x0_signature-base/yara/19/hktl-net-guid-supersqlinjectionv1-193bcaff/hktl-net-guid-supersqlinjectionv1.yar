rule HKTL_NET_GUID_SuperSQLInjectionV1 {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/shack2/SuperSQLInjectionV1"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2025-08-15"
        id = "247bef0d-7873-51c7-97b8-1be6dfe7708d"
    strings:
        $typelibguid0lo = "d5688068-fc89-467d-913f-037a785caca7" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}