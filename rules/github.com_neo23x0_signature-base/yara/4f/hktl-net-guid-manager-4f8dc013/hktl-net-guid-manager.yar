rule HKTL_NET_GUID_Manager {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/TheWover/Manager"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2025-08-15"
        id = "eef65d2c-ddbc-50c3-a6a0-e7032a55e92d"
    strings:
        $typelibguid0lo = "dda73ee9-0f41-4c09-9cad-8215abd60b33" ascii wide
        $typelibguid1lo = "6a0f2422-d4d1-4b7e-84ad-56dc0fd2dfc5" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}