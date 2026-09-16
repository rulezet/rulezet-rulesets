rule HKTL_NET_GUID_Stealth_Kid_RAT {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/ctsecurity/Stealth-Kid-RAT"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "f26e040a-dcc7-518f-89f2-3333f83fa14a"
    strings:
        $typelibguid0lo = "bf43cd33-c259-4711-8a0e-1a5c6c13811d" ascii wide
        $typelibguid1lo = "e5b9df9b-a9e4-4754-8731-efc4e2667d88" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}