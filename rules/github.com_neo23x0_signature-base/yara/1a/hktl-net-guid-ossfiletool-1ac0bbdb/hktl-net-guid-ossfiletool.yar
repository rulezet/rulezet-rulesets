rule HKTL_NET_GUID_OSSFileTool {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/B1eed/OSSFileTool"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "fa9aeae1-2aa5-51af-81e2-22a1b6fcda81"
    strings:
        $typelibguid0lo = "207aca5d-dcd6-41fb-8465-58b39efcde8b" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}