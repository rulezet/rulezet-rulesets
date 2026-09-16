rule HKTL_NET_GUID_DarkEye {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/K1ngSoul/DarkEye"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "5dc6702f-a398-5be2-9df8-9a2ddc636a1f"
    strings:
        $typelibguid0lo = "0bdb9c65-14ed-4205-ab0c-ea2151866a7f" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}