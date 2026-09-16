rule HKTL_NET_GUID_DarkFender {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0xyg3n/DarkFender"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "0aea5e05-7788-5581-8bcc-d2e75a291dd9"
    strings:
        $typelibguid0lo = "12fdf7ce-4a7c-41b6-9b32-766ddd299beb" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}