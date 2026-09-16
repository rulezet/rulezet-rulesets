rule HKTL_NET_GUID_SharpC2 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/SharpC2/SharpC2"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "2ed6d74e-2b95-5c70-807a-4da5e62f5853"
    strings:
        $typelibguid0lo = "62b9ee4f-1436-4098-9bc1-dd61b42d8b81" ascii wide
        $typelibguid1lo = "d2f17a91-eb2d-4373-90bf-a26e46c68f76" ascii wide
        $typelibguid2lo = "a9db9fcc-7502-42cd-81ec-3cd66f511346" ascii wide
        $typelibguid3lo = "ca6cc2ee-75fd-4f00-b687-917fa55a4fae" ascii wide
        $typelibguid4lo = "a1167b68-446b-4c0c-a8b8-2a7278b67511" ascii wide
        $typelibguid5lo = "4d8c2a88-1da5-4abe-8995-6606473d7cf1" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}