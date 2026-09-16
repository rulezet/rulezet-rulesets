rule HKTL_NET_GUID_RestrictedAdmin {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/GhostPack/RestrictedAdmin"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-18"
        modified = "2025-08-15"
        id = "1b3572a5-bb21-58bb-91f9-963a0a17d699"
    strings:
        $typelibguid0lo = "79f11fc0-abff-4e1f-b07c-5d65653d8952" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}