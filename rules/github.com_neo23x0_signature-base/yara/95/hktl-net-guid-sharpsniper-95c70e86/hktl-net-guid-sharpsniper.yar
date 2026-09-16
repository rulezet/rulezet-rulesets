rule HKTL_NET_GUID_SharpSniper {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/HunnicCyber/SharpSniper"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-29"
        modified = "2025-08-15"
        id = "14e6a3b8-5e1f-5dd8-9b51-22522ac317e7"
    strings:
        $typelibguid0lo = "c8bb840c-04ce-4b60-a734-faf15abf7b18" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}