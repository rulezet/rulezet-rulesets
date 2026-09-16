rule HKTL_NET_GUID_SharpWMI_2 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/GhostPack/SharpWMI"
        old_rule_name = "HKTL_NET_GUID_SharpWMI"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "e6ab2f5e-2a5a-5be9-9b66-96cb745fd199"
    strings:
        $typelibguid0lo = "6dd22880-dac5-4b4d-9c91-8c35cc7b8180" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}