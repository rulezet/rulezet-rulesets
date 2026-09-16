rule HKTL_NET_GUID_fakelogonscreen {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/bitsadmin/fakelogonscreen"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "cc20290c-3f34-5e81-9337-c582f1ee7ade"
    strings:
        $typelibguid0lo = "d35a55bd-3189-498b-b72f-dc798172e505" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}