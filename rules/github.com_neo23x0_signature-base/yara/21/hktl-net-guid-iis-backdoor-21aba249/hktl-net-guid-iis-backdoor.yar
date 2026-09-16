rule HKTL_NET_GUID_IIS_backdoor {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/WBGlIl/IIS_backdoor"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "44264dd9-f8e9-5a60-847f-94378e07a327"
    strings:
        $typelibguid0lo = "3fda4aa9-6fc1-473f-9048-7edc058c4f65" ascii wide
        $typelibguid1lo = "73ca4159-5d13-4a27-8965-d50c41ab203c" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}