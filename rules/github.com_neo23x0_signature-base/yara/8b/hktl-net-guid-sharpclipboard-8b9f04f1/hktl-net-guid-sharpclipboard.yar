rule HKTL_NET_GUID_SharpClipboard {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/slyd0g/SharpClipboard"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "fd1b7786-8853-5858-ab03-da350e44f738"
    strings:
        $typelibguid0lo = "97484211-4726-4129-86aa-ae01d17690be" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}