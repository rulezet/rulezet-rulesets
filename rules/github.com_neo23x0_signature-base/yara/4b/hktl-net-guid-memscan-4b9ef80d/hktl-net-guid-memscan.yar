rule HKTL_NET_GUID_memscan {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/nccgroup/memscan"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "35175fe1-a583-50d1-8b0c-71f19b898817"
    strings:
        $typelibguid0lo = "79462f87-8418-4834-9356-8c11e44ce189" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}