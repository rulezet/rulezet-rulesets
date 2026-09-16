rule HKTL_NET_GUID_Snaffler {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/SnaffCon/Snaffler"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "d4b9a8c5-e0d9-5c85-af81-05f6e0f52bff"
    strings:
        $typelibguid0lo = "2aa060b4-de88-4d2a-a26a-760c1cefec3e" ascii wide
        $typelibguid1lo = "b118802d-2e46-4e41-aac7-9ee890268f8b" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}