rule HKTL_NET_GUID_SharpFruit {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rvrsh3ll/SharpFruit"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "bf318530-b17d-5275-84b2-c284528bdae6"
    strings:
        $typelibguid0lo = "3da2f6de-75be-4c9d-8070-08da45e79761" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}