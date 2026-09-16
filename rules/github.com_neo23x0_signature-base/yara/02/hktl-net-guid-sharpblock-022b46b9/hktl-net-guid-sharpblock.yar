rule HKTL_NET_GUID_SharpBlock {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/CCob/SharpBlock"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "b84538da-1b0e-50c7-abfa-e93d6de5a49b"
    strings:
        $typelibguid0lo = "3cf25e04-27e4-4d19-945e-dadc37c81152" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}