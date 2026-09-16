rule HKTL_NET_GUID_DotNetAVBypass_Master {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/lockfale/DotNetAVBypass-Master"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "4004271b-4fbe-58bb-9613-a077e76324b3"
    strings:
        $typelibguid0lo = "4854c8dc-82b0-4162-86e0-a5bbcbc10240" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}