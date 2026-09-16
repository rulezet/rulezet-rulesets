rule HKTL_NET_GUID_EvilWMIProvider {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/sunnyc7/EvilWMIProvider"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "3a6cf00e-28c4-5e6f-a28d-b3f28fca6eed"
    strings:
        $typelibguid0lo = "a4020626-f1ec-4012-8b17-a2c8a0204a4b" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}