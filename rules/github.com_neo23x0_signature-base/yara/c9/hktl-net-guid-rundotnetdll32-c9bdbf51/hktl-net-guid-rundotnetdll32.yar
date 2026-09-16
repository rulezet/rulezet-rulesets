rule HKTL_NET_GUID_rundotnetdll32 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0xbadjuju/rundotnetdll32"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "266c8add-d2ca-5e46-8594-5d190447d133"
    strings:
        $typelibguid0lo = "a766db28-94b6-4ed1-aef9-5200bbdd8ca7" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}