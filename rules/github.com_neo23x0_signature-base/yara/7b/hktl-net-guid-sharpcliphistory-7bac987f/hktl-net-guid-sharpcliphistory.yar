rule HKTL_NET_GUID_SharpClipHistory {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/FSecureLABS/SharpClipHistory"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-21"
        modified = "2025-08-15"
        id = "89ca4717-a4ec-5371-8dc3-bdb9933384af"
    strings:
        $typelibguid0lo = "1126d5b4-efc7-4b33-a594-b963f107fe82" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}