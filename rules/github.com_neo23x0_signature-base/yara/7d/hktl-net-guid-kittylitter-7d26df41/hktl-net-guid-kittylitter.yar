rule HKTL_NET_GUID_KittyLitter {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/djhohnstein/KittyLitter"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-22"
        modified = "2025-08-15"
        id = "f457b91f-4adb-5be6-b9c2-f6cc39d4bdaf"
    strings:
        $typelibguid0lo = "449cf269-4798-4268-9a0d-9a17a08869ba" ascii wide
        $typelibguid1lo = "e7a509a4-2d44-4e10-95bf-b86cb7767c2c" ascii wide
        $typelibguid2lo = "b2b8dd4f-eba6-42a1-a53d-9a00fe785d66" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}