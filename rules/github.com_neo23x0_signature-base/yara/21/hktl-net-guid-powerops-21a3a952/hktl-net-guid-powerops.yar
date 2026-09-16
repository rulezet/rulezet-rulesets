rule HKTL_NET_GUID_PowerOPS {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/fdiskyou/PowerOPS"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-21"
        modified = "2025-08-15"
        id = "3ef9f099-13c9-5b6f-8615-232240530078"
    strings:
        $typelibguid0lo = "2a3c5921-7442-42c3-8cb9-24f21d0b2414" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}