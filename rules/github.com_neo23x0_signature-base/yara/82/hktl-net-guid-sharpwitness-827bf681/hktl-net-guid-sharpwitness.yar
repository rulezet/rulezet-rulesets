rule HKTL_NET_GUID_SharpWitness {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rasta-mouse/SharpWitness"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "5e707da6-b2dd-511e-89ad-d19b93e8fca6"
    strings:
        $typelibguid0lo = "b9f6ec34-4ccc-4247-bcef-c1daab9b4469" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}