rule HKTL_NET_GUID_SharpLocker {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Pickfordmatt/SharpLocker"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "9525422a-d670-5475-abdc-b7ecd1ab9943"
    strings:
        $typelibguid0lo = "a6f8500f-68bc-4efc-962a-6c6e68d893af" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}