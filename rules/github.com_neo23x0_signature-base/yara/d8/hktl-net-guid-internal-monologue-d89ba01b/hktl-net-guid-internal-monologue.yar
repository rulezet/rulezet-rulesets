rule HKTL_NET_GUID_Internal_Monologue {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/eladshamir/Internal-Monologue"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "ce2773a2-b0b7-560e-ba21-3f018ddcacb3"
    strings:
        $typelibguid0lo = "0c0333db-8f00-4b68-b1db-18a9cacc1486" ascii wide
        $typelibguid1lo = "84701ace-c584-4886-a3cf-76c57f6e801a" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}