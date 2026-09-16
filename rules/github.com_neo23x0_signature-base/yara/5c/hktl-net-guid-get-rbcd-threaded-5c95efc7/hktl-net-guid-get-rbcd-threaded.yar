rule HKTL_NET_GUID_Get_RBCD_Threaded {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/FatRodzianko/Get-RBCD-Threaded"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-22"
        modified = "2025-08-15"
        id = "fdef6dc3-da1a-5a98-a822-94e443981fdd"
    strings:
        $typelibguid0lo = "e20dc2ed-6455-4101-9d78-fccac1cb7a18" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}