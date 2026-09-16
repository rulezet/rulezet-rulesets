rule HKTL_NET_GUID_MemoryMapper {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/jasondrawdy/MemoryMapper"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "c978be10-315c-54e7-afea-f97e9a5f2d18"
    strings:
        $typelibguid0lo = "b9fbf3ac-05d8-4cd5-9694-b224d4e6c0ea" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}