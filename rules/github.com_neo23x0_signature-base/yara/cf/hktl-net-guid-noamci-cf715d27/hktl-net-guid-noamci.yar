rule HKTL_NET_GUID_NoAmci {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/med0x2e/NoAmci"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "5fab1551-9d35-53cf-a04f-c14370119553"
    strings:
        $typelibguid0lo = "352e80ec-72a5-4aa6-aabe-4f9a20393e8e" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}