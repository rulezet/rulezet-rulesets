rule HKTL_NET_GUID_Offensive__NET {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/mrjamiebowman/Offensive-.NET"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "b98495fb-0338-5042-a7ce-d117204eb91e"
    strings:
        $typelibguid0lo = "11fe5fae-b7c1-484a-b162-d5578a802c9c" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}