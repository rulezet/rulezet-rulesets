rule HKTL_NET_GUID_Keylogger {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/BlackVikingPro/Keylogger"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "0576756e-26d5-5165-b621-917126a75a38"
    strings:
        $typelibguid0lo = "7afbc9bf-32d9-460f-8a30-35e30aa15879" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}