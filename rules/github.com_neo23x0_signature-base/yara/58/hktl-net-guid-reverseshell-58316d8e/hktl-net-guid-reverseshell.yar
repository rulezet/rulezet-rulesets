rule HKTL_NET_GUID_ReverseShell {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/chango77747/ReverseShell"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "876932d5-a65d-5230-9cb8-24038ad8af0d"
    strings:
        $typelibguid0lo = "980109e4-c988-47f9-b2b3-88d63fababdc" ascii wide
        $typelibguid1lo = "8abe8da1-457e-4933-a40d-0958c8925985" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}