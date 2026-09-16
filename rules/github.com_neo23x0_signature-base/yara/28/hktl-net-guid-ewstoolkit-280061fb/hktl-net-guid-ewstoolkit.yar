rule HKTL_NET_GUID_EWSToolkit {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rasta-mouse/EWSToolkit"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "acde7744-d17f-5e47-a5e2-ff4f4c4d8093"
    strings:
        $typelibguid0lo = "ca536d67-53c9-43b5-8bc8-9a05fdc567ed" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}