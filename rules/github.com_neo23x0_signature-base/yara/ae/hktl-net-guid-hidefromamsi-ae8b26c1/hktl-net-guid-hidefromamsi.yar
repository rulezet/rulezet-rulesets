rule HKTL_NET_GUID_HideFromAMSI {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0r13lc0ch4v1/HideFromAMSI"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "0fa1ce82-b662-5e18-a5da-8359c96cd6e9"
    strings:
        $typelibguid0lo = "b91d2d44-794c-49b8-8a75-2fbec3fe3fe3" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}