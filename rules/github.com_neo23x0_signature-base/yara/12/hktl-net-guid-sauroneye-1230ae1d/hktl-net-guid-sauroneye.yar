rule HKTL_NET_GUID_SauronEye {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/vivami/SauronEye"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "3b624dde-a63e-58ac-a4db-af931f1d8553"
    strings:
        $typelibguid0lo = "0f43043d-8957-4ade-a0f4-25c1122e8118" ascii wide
        $typelibguid1lo = "086bf0ca-f1e4-4e8f-9040-a8c37a49fa26" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}