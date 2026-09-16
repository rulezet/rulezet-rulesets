rule HKTL_NET_GUID_HWIDbypass {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/yunseok/HWIDbypass"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "62b0541b-6eec-546e-8445-85d25bb0d784"
    strings:
        $typelibguid0lo = "47e08791-d124-4746-bc50-24bd1ee719a6" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}