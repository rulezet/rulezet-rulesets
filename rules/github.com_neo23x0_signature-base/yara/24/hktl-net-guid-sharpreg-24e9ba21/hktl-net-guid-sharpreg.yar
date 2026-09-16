rule HKTL_NET_GUID_SharpReg {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/jnqpblc/SharpReg"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2025-08-15"
        id = "d89b07b0-bb29-5c77-888b-322e439b4c82"
    strings:
        $typelibguid0lo = "8ef25b00-ed6a-4464-bdec-17281a4aa52f" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}