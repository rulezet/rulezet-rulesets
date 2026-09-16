rule HKTL_NET_GUID_Adamantium_Thief {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/LimerBoy/Adamantium-Thief"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "82225b2e-ab4a-50b8-a3fd-7ad4947d052e"
    strings:
        $typelibguid0lo = "e6104bc9-fea9-4ee9-b919-28156c1f2ede" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}