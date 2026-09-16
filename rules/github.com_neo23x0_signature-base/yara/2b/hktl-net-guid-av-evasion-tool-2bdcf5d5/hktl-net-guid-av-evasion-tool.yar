rule HKTL_NET_GUID_AV_Evasion_Tool {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/1y0n/AV_Evasion_Tool"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "d4257465-38a0-56b9-8402-b92e21b96cb0"
    strings:
        $typelibguid0lo = "1937ee16-57d7-4a5f-88f4-024244f19dc6" ascii wide
        $typelibguid1lo = "7898617d-08d2-4297-adfe-5edd5c1b828b" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}