rule HKTL_NET_GUID_SneakyService {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/malcomvetter/SneakyService"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "d02d34f0-7aa1-5110-b7ea-670b5fb98150"
    strings:
        $typelibguid0lo = "897819d5-58e0-46a0-8e1a-91ea6a269d84" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}