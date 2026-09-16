rule HKTL_NET_GUID_Rubeus {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/GhostPack/Rubeus"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "54638fe4-84b5-51a8-8c88-9c50ab09ff49"
    strings:
        $typelibguid0lo = "658c8b7f-3664-4a95-9572-a3e5871dfc06" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}