rule HKTL_NET_GUID_Inferno {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/LimerBoy/Inferno"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "af2d9832-c7f9-5879-a19b-a3c4d91b8b3f"
    strings:
        $typelibguid0lo = "26d498f7-37ae-476c-97b0-3761e3a919f0" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}