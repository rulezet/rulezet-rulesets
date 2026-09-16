rule HKTL_NET_GUID_BYTAGE {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/KNIF/BYTAGE"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "4f87ca2c-3ac1-5733-893e-79665b80ffc3"
    strings:
        $typelibguid0lo = "8e46ba56-e877-4dec-be1e-394cb1b5b9de" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}