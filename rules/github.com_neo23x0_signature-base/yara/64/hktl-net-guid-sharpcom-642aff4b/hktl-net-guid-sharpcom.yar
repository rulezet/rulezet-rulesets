rule HKTL_NET_GUID_SharpCOM {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rvrsh3ll/SharpCOM"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "94da3da4-a8aa-5735-9a04-1f2447a330aa"
    strings:
        $typelibguid0lo = "51960f7d-76fe-499f-afbd-acabd7ba50d1" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}