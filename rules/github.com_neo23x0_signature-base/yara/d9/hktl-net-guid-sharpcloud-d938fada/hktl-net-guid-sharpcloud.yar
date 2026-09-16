rule HKTL_NET_GUID_SharpCloud {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/chrismaddalena/SharpCloud"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-22"
        modified = "2025-08-15"
        id = "048b0239-ea13-58ff-af35-fd505b4c977a"
    strings:
        $typelibguid0lo = "ca4e257e-69c1-45c5-9375-ba7874371892" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}