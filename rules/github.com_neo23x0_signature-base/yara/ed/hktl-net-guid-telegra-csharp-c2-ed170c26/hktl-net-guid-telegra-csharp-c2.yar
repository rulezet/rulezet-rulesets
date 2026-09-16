rule HKTL_NET_GUID_Telegra_Csharp_C2 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/sf197/Telegra_Csharp_C2"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "495a5f3e-cf05-5a66-b01c-8176ded88768"
    strings:
        $typelibguid0lo = "1d79fabc-2ba2-4604-a4b6-045027340c85" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}