rule HKTL_NET_GUID_DLL_Injection {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/ihack4falafel/DLL-Injection"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "aec4fc28-9aa2-5eef-9fb1-d187a83a72b3"
    strings:
        $typelibguid0lo = "3d7e1433-f81a-428a-934f-7cc7fcf1149d" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}