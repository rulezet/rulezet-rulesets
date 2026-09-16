rule HKTL_NET_GUID_SharpSQLPwn {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/lefayjey/SharpSQLPwn.git"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2022-11-21"
        modified = "2025-08-15"
        id = "b533d61a-8693-5c3c-8b31-2117262cad4e"
    strings:
        $typelibguid0lo = "c442ea6a-9aa1-4d9c-9c9d-7560a327089c" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}