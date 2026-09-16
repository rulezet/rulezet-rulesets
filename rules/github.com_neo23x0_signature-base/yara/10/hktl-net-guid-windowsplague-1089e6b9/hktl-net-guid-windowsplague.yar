rule HKTL_NET_GUID_WindowsPlague {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/RITRedteam/WindowsPlague"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "89729c43-ae01-5c1f-af04-06d7a6c4e7fc"
    strings:
        $typelibguid0lo = "cdf8b024-70c9-413a-ade3-846a43845e99" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}