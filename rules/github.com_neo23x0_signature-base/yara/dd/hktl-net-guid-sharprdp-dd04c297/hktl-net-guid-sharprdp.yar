rule HKTL_NET_GUID_SharpRDP {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0xthirteen/SharpRDP"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "d316ec0b-0313-52bb-923d-512fa08112f9"
    strings:
        $typelibguid0lo = "f1df1d0f-ff86-4106-97a8-f95aaf525c54" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}