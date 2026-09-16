rule HKTL_NET_GUID_SharpHandler {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/jfmaes/SharpHandler"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2025-08-15"
        id = "b71198a9-4d00-5d75-bc36-7c40655c84a3"
    strings:
        $typelibguid0lo = "46e39aed-0cff-47c6-8a63-6826f147d7bd" ascii wide
        $typelibguid1lo = "11dc83c6-8186-4887-b228-9dc4fd281a23" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}