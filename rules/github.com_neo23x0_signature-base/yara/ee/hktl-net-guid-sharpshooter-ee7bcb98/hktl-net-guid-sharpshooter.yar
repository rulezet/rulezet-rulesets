rule HKTL_NET_GUID_SharpShooter {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/mdsecactivebreach/SharpShooter"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "a59e6fe9-dbaf-5830-8cf1-485ff4dd939a"
    strings:
        $typelibguid0lo = "56598f1c-6d88-4994-a392-af337abe5777" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}