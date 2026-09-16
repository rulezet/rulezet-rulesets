rule HKTL_NET_GUID_SharpAllowedToAct {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/pkb1s/SharpAllowedToAct"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2025-08-15"
        id = "13b7f5e0-4d34-533d-a182-b3fe7c93ca43"
    strings:
        $typelibguid0lo = "dac5448a-4ad1-490a-846a-18e4e3e0cf9a" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}