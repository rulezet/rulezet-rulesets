rule HKTL_NET_GUID_LdapSignCheck {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/cube0x0/LdapSignCheck"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-15"
        modified = "2025-08-15"
        id = "a8b902f0-61a5-509e-8307-79bf557e5f61"
    strings:
        $typelibguid0lo = "21f398a9-bc35-4bd2-b906-866f21409744" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}