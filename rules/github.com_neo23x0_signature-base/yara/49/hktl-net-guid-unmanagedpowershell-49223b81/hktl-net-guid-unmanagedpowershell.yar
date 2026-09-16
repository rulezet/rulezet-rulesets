rule HKTL_NET_GUID_UnmanagedPowerShell {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/leechristensen/UnmanagedPowerShell"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "49ff1362-0ac5-580d-97f3-516f2a10072b"
    strings:
        $typelibguid0lo = "dfc4eebb-7384-4db5-9bad-257203029bd9" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}