rule HKTL_NET_GUID_Mythic {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/its-a-feature/Mythic"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-29"
        modified = "2025-08-15"
        id = "44237fac-1526-5587-83a1-61d7a54f7da9"
    strings:
        $typelibguid0lo = "91f7a9da-f045-4239-a1e9-487ffdd65986" ascii wide
        $typelibguid1lo = "0405205c-c2a0-4f9a-a221-48b5c70df3b6" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}