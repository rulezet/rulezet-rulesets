rule HKTL_NET_GUID_AllTheThings {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/johnjohnsp1/AllTheThings"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "c35160cb-ad31-5195-a7c6-0af91a58737d"
    strings:
        $typelibguid0lo = "0547ff40-5255-42a2-beb7-2ff0dbf7d3ba" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}