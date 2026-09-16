rule HKTL_NET_GUID_ysoserial_net {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/pwntester/ysoserial.net"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "80483cd4-76e6-5629-bed7-4ae2e455222c"
    strings:
        $typelibguid0lo = "e1e8c029-f7cd-4bd1-952e-e819b41520f0" ascii wide
        $typelibguid1lo = "6b40fde7-14ea-4f57-8b7b-cc2eb4a25e6c" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}