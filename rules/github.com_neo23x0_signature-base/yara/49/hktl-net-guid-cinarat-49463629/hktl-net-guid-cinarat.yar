rule HKTL_NET_GUID_CinaRAT {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/wearelegal/CinaRAT"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "c6b4c919-0fc6-5096-b29b-963142a2c831"
    strings:
        $typelibguid0lo = "8586f5b1-2ef4-4f35-bd45-c6206fdc0ebc" ascii wide
        $typelibguid1lo = "fe184ab5-f153-4179-9bf5-50523987cf1f" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}