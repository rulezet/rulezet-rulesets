rule HKTL_NET_GUID_SharpBox {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/P1CKLES/SharpBox"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "fda1a67f-d746-5ddb-a33f-97d608b13bc9"
    strings:
        $typelibguid0lo = "616c1afb-2944-42ed-9951-bf435cadb600" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}