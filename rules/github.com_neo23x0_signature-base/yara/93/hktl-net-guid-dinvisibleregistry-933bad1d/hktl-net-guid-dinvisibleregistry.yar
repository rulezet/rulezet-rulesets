rule HKTL_NET_GUID_DInvisibleRegistry {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NVISO-BE/DInvisibleRegistry"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "98409bbe-6346-5825-b7f7-c1afeac2b038"
    strings:
        $typelibguid0lo = "31d576fb-9fb9-455e-ab02-c78981634c65" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}