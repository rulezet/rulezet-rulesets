rule HKTL_NET_GUID_RunShellcode {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/zerosum0x0/RunShellcode"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "249da967-68b0-59b1-b414-4eb4fe67b8f3"
    strings:
        $typelibguid0lo = "a3ec18a3-674c-4131-a7f5-acbed034b819" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}