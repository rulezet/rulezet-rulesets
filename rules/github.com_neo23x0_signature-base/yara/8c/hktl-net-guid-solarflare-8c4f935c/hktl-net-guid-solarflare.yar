rule HKTL_NET_GUID_SolarFlare {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/mubix/solarflare"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-15"
        modified = "2025-08-15"
        id = "3645e14c-6025-59fa-a5a2-d8dacba8cd94"
    strings:
        $typelibguid0lo = "ca60e49e-eee9-409b-8d1a-d19f1d27b7e4" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}