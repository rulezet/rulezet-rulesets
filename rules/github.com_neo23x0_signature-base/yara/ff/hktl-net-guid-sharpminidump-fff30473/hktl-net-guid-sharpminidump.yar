rule HKTL_NET_GUID_SharpMiniDump {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/b4rtik/SharpMiniDump"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "e91e6711-d992-5a8a-97e6-1ed7847f38a4"
    strings:
        $typelibguid0lo = "6ffccf81-6c3c-4d3f-b15f-35a86d0b497f" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}