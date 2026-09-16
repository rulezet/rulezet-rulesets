rule HKTL_NET_GUID_Change_Lockscreen {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/nccgroup/Change-Lockscreen"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "a817c6e8-95f9-56c6-97b8-4be06658629f"
    strings:
        $typelibguid0lo = "78642ab3-eaa6-4e9c-a934-e7b0638bc1cc" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}