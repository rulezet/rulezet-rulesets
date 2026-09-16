rule HKTL_NET_GUID_SharpCrashEventLog {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/slyd0g/SharpCrashEventLog"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2025-08-15"
        id = "85d31989-ad96-5005-a747-8a19a67fdd80"
    strings:
        $typelibguid0lo = "98cb495f-4d47-4722-b08f-cefab2282b18" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}