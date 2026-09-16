rule HKTL_NET_GUID_logger {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/xxczaki/logger"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "82937fef-8280-5bc6-af4a-55c5cb3a7553"
    strings:
        $typelibguid0lo = "9e92a883-3c8b-4572-a73e-bb3e61cfdc16" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}