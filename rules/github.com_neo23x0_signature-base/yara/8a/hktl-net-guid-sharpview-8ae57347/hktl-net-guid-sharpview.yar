rule HKTL_NET_GUID_SharpView {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/tevora-threat/SharpView"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-22"
        modified = "2025-08-15"
        id = "2ae1bc26-c137-55ce-ae2e-3204ff07f671"
    strings:
        $typelibguid0lo = "22a156ea-2623-45c7-8e50-e864d9fc44d3" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}