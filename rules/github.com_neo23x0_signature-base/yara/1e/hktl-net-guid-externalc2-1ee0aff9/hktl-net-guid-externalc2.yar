rule HKTL_NET_GUID_ExternalC2 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/ryhanson/ExternalC2"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "1bbdfbb9-a3e8-5ffe-9db9-b50937e6a14d"
    strings:
        $typelibguid0lo = "7266acbb-b10d-4873-9b99-12d2043b1d4e" ascii wide
        $typelibguid1lo = "5d9515d0-df67-40ed-a6b2-6619620ef0ef" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}