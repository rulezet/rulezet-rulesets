rule HKTL_NET_GUID_LockLess {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/GhostPack/LockLess"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2025-08-15"
        id = "f9b31f57-d721-5b6c-be63-b8309cba788a"
    strings:
        $typelibguid0lo = "a91421cb-7909-4383-ba43-c2992bbbac22" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}