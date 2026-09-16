rule HKTL_NET_GUID_scout {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/jaredhaight/scout"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "cd24cca7-3bc0-5e7a-9817-dc3b26ec8358"
    strings:
        $typelibguid0lo = "d9c76e82-b848-47d4-8f22-99bf22a8ee11" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}