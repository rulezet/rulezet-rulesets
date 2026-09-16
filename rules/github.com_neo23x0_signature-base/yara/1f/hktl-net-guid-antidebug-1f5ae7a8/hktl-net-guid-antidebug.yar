rule HKTL_NET_GUID_AntiDebug {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/malcomvetter/AntiDebug"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "f381081b-d0cb-593d-ad3d-28816f770b67"
    strings:
        $typelibguid0lo = "997265c1-1342-4d44-aded-67964a32f859" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}