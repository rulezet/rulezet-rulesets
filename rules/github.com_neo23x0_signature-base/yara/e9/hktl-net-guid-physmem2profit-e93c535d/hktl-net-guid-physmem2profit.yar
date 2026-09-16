rule HKTL_NET_GUID_physmem2profit {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/FSecureLABS/physmem2profit"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "75a27970-c469-53da-b0c3-b3d0faea0b6f"
    strings:
        $typelibguid0lo = "814708c9-2320-42d2-a45f-31e42da06a94" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}