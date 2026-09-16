rule HKTL_NET_GUID_SharpSSDP {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/rvrsh3ll/SharpSSDP"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-22"
        modified = "2025-08-15"
        id = "8441e940-ab7c-5467-9db8-35f71bd57580"
    strings:
        $typelibguid0lo = "6e383de4-de89-4247-a41a-79db1dc03aaa" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}