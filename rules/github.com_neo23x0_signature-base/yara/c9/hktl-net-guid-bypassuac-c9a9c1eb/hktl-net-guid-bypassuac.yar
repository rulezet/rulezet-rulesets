rule HKTL_NET_GUID_BypassUAC {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/cnsimo/BypassUAC"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "327f581e-1d8c-5d20-bdd7-a29810c619c9"
    strings:
        $typelibguid0lo = "4e7c140d-bcc4-4b15-8c11-adb4e54cc39a" ascii wide
        $typelibguid1lo = "cec553a7-1370-4bbc-9aae-b2f5dbde32b0" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}