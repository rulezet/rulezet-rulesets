rule HKTL_NET_GUID_CloneVault {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/mdsecactivebreach/CloneVault"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2025-08-15"
        id = "3340a095-d926-5c85-b7ed-03151712538d"
    strings:
        $typelibguid0lo = "0a344f52-6780-4d10-9a4a-cb9439f9d3de" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}