rule HKTL_NET_GUID_DotNetToJScript {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/tyranid/DotNetToJScript"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "31827074-fc63-5690-b6c7-8e89daacc07f"
    strings:
        $typelibguid0lo = "7e3f231c-0d0b-4025-812c-0ef099404861" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}