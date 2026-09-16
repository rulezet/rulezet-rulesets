rule HKTL_NET_GUID_SharpDump {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/GhostPack/SharpDump"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "b613092f-9006-5405-b07e-59737410ac1e"
    strings:
        $typelibguid0lo = "79c9bba3-a0ea-431c-866c-77004802d8a0" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}