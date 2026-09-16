rule HKTL_NET_GUID_SharpCookieMonster {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/m0rv4i/SharpCookieMonster"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "87be6949-f4f5-5a5a-b804-c627ed0f4355"
    strings:
        $typelibguid0lo = "566c5556-1204-4db9-9dc8-a24091baaa8e" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}