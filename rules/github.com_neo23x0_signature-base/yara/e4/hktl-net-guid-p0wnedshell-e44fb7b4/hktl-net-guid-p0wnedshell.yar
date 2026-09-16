rule HKTL_NET_GUID_p0wnedShell {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Cn33liz/p0wnedShell"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "390b94d1-dda9-5a85-80ae-c79a3f7b0b9d"
    strings:
        $typelibguid0lo = "2e9b1462-f47c-48ca-9d85-004493892381" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}