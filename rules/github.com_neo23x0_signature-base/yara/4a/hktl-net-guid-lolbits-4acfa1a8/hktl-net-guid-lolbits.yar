rule HKTL_NET_GUID_LOLBITS {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Kudaes/LOLBITS"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "66454ac0-742b-51a3-ac45-1ac9606e8b89"
    strings:
        $typelibguid0lo = "29d09aa4-ea0c-47c2-973c-1d768087d527" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}