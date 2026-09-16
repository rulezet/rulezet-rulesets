rule HKTL_NET_GUID_EvilFOCA {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/ElevenPaths/EvilFOCA"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "2b2f5f6f-4224-5013-9e85-0ac088826bea"
    strings:
        $typelibguid0lo = "f26bdb4a-5846-4bec-8f52-3c39d32df495" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}