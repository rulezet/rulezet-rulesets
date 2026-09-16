rule HKTL_NET_GUID_SharpCall {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/jhalon/SharpCall"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "172415b6-0383-5da4-a88f-8ebe5daf9294"
    strings:
        $typelibguid0lo = "c1b0a923-0f17-4bc8-ba0f-c87aff43e799" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}