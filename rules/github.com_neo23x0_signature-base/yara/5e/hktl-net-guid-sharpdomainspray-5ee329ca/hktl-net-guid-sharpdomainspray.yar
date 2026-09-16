rule HKTL_NET_GUID_SharpDomainSpray {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/HunnicCyber/SharpDomainSpray"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "cffd3350-4a86-5035-ab15-adbc3ac2a0e9"
    strings:
        $typelibguid0lo = "76ffa92b-429b-4865-970d-4e7678ac34ea" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}