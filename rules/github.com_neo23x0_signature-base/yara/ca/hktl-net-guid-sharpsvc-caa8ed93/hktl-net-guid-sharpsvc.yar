rule HKTL_NET_GUID_SharpSvc {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/jnqpblc/SharpSvc"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2025-08-15"
        id = "cbc1d7d4-f3b4-5d02-84ae-621398cb7b51"
    strings:
        $typelibguid0lo = "52856b03-5acd-45e0-828e-13ccb16942d1" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}