rule HKTL_NET_GUID_UAC_SilentClean {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/EncodeGroup/UAC-SilentClean"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "2dde9632-10c5-5c91-8bd9-2fb80d6f0c49"
    strings:
        $typelibguid0lo = "948152a4-a4a1-4260-a224-204255bfee72" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}