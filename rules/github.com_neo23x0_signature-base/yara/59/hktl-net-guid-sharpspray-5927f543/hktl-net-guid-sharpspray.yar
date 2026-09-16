rule HKTL_NET_GUID_SharpSpray {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/jnqpblc/SharpSpray"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "e9312c96-be10-5942-a4da-1fe708cc6699"
    strings:
        $typelibguid0lo = "51c6e016-1428-441d-82e9-bb0eb599bbc8" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}