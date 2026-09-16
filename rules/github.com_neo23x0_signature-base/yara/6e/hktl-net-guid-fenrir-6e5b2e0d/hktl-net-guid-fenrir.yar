rule HKTL_NET_GUID_Fenrir {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/nccgroup/Fenrir"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "cfc6312d-5997-5261-b771-c7f3f30bf86c"
    strings:
        $typelibguid0lo = "aecec195-f143-4d02-b946-df0e1433bd2e" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}