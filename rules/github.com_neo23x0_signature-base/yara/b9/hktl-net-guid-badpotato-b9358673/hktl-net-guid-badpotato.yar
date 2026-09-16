rule HKTL_NET_GUID_BadPotato {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/BeichenDream/BadPotato"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "8bee12fc-fc29-5256-b559-d914ef202c0c"
    strings:
        $typelibguid0lo = "0527a14f-1591-4d94-943e-d6d784a50549" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}