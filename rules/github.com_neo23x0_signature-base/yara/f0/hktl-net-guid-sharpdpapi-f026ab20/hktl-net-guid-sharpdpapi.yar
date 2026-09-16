rule HKTL_NET_GUID_SharpDPAPI {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/GhostPack/SharpDPAPI"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "1394323f-b336-548f-925c-c276d439e9eb"
    strings:
        $typelibguid0lo = "5f026c27-f8e6-4052-b231-8451c6a73838" ascii wide
        $typelibguid1lo = "2f00a05b-263d-4fcc-846b-da82bd684603" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}