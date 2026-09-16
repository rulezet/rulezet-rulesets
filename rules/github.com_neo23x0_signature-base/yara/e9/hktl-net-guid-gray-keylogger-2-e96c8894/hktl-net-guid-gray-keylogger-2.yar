rule HKTL_NET_GUID_gray_keylogger_2 {
    meta:
        description = "Detects VB.NET red/black-team tools via typelibguid"
        reference = "https://github.com/graysuit/gray-keylogger-2"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-30"
        modified = "2025-08-15"
        id = "40ab8103-9151-5a5c-8b70-ab3bfd3896f9"
    strings:
        $typelibguid0lo = "e94ca3ff-c0e5-4d1a-ad5e-f6ebbe365067" ascii wide
        $typelibguid1lo = "1ed07564-b411-4626-88e5-e1cd8ecd860a" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}