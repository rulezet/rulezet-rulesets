rule HKTL_NET_GUID_SharpWMI_1 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/QAX-A-Team/sharpwmi"
        old_rule_name = "HKTL_NET_GUID_sharpwmi"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "cd5a1c7b-a45a-5541-b1b0-cf19c991ed22"
    strings:
        $typelibguid0lo = "bb357d38-6dc1-4f20-a54c-d664bd20677e" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}