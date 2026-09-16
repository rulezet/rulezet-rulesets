rule HKTL_NET_GUID_SharpDir {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/jnqpblc/SharpDir"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2025-08-15"
        id = "f64ed564-d198-59e8-9abe-b2814b95c85f"
    strings:
        $typelibguid0lo = "c7a07532-12a3-4f6a-a342-161bb060b789" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}