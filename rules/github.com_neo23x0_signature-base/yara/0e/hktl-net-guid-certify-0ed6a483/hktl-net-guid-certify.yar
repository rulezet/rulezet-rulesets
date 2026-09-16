rule HKTL_NET_GUID_Certify {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/GhostPack/Certify"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-06"
        modified = "2025-08-11"
        hash = "da585a8d4985082873cb86204d546d3f53668e034c61e42d247b11e92b5e8fc3"
        id = "69f120fe-bd4d-59ba-b1b9-528ab300e450"
    strings:
        $typelibguid0_v1 = "64524ca5-e4d0-41b3-acc3-3bdbefd40c97" ascii wide
        $typelibguid0_v2 = "15cfadd8-5f6c-424b-81dc-c028312d025f" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}