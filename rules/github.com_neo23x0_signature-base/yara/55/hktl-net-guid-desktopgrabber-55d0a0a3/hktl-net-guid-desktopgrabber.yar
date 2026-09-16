rule HKTL_NET_GUID_DesktopGrabber {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/DesktopGrabber"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "7db07291-d6d4-5527-a879-27f899dbd6fe"
    strings:
        $typelibguid0lo = "e6aa0cd5-9537-47a0-8c85-1fbe284a4380" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}