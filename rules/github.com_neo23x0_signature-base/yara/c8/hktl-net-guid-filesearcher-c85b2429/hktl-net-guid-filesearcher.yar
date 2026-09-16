rule HKTL_NET_GUID_FileSearcher {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NVISO-BE/FileSearcher"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "1b5f1f68-f87b-5e60-94a4-e2556b4e6c5d"
    strings:
        $typelibguid0lo = "2c879479-5027-4ce9-aaac-084db0e6d630" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}