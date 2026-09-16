rule HKTL_NET_GUID_Whisker {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/eladshamir/Whisker"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-22"
        modified = "2025-08-15"
        id = "ecb0c59f-2111-58d9-8dc9-dfe005cad3be"
    strings:
        $typelibguid0lo = "42750ac0-1bff-4f25-8c9d-9af144403bad" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}