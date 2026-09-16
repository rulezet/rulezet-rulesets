rule HKTL_NET_GUID_RedSharp {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/padovah4ck/RedSharp"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "2aa62d61-075c-5664-a7fc-2b9d84b954ed"
    strings:
        $typelibguid0lo = "30b2e0cf-34dd-4614-a5ca-6578fb684aea" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}