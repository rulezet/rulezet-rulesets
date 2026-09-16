rule HKTL_NET_GUID_Farmer {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/mdsecactivebreach/Farmer"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-22"
        modified = "2025-08-15"
        id = "f69745b9-4ebd-547a-9af3-bc340b076e5d"
    strings:
        $typelibguid0lo = "37da2573-d9b5-4fc2-ae11-ccb6130cea9f" ascii wide
        $typelibguid1lo = "49acf861-1c10-49a1-bf26-139a3b3a9227" ascii wide
        $typelibguid2lo = "9a6c028f-423f-4c2c-8db3-b3499139b822" ascii wide
        $typelibguid3lo = "1c896837-e729-46a9-92b9-3bbe7ac2c90d" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}