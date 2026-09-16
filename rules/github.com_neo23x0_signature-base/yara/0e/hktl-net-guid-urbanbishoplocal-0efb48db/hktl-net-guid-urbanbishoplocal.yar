rule HKTL_NET_GUID_UrbanBishopLocal {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/slyd0g/UrbanBishopLocal"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "53b690ec-7d20-5e46-b368-b458ce56073d"
    strings:
        $typelibguid0lo = "88b8515e-a0e8-4208-a9a0-34b01d7ba533" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}