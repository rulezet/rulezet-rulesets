rule HKTL_NET_GUID_NoMSBuild {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rvrsh3ll/NoMSBuild"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "9bc0661d-c60f-582b-8f88-87e3dfa13ddd"
    strings:
        $typelibguid0lo = "034a7b9f-18df-45da-b870-0e1cef500215" ascii wide
        $typelibguid1lo = "59b449d7-c1e8-4f47-80b8-7375178961db" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}