rule HKTL_NET_GUID_SharpScribbles {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/V1V1/SharpScribbles"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2025-08-15"
        id = "47125b76-9388-5372-8810-d198f623367a"
    strings:
        $typelibguid0lo = "aa61a166-31ef-429d-a971-ca654cd18c3b" ascii wide
        $typelibguid1lo = "0dc1b824-c6e7-4881-8788-35aecb34d227" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}