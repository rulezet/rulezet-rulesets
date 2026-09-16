rule HKTL_NET_GUID_SharpSocks {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/nettitude/SharpSocks"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "343061d9-e24e-5d49-939f-b94c295b17ac"
    strings:
        $typelibguid0lo = "2f43992e-5703-4420-ad0b-17cb7d89c956" ascii wide
        $typelibguid1lo = "86d10a34-c374-4de4-8e12-490e5e65ddff" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}