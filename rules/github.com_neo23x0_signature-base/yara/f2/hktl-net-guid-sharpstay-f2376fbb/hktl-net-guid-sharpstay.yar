rule HKTL_NET_GUID_SharpStay {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0xthirteen/SharpStay"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "e5bde5a9-8e09-59ce-ad01-e29836813cf8"
    strings:
        $typelibguid0lo = "2963c954-7b1e-47f5-b4fa-2fc1f0d56aea" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}