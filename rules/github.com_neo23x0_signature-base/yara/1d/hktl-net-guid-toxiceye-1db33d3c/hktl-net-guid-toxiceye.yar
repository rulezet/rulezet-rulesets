rule HKTL_NET_GUID_ToxicEye {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/LimerBoy/ToxicEye"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "0b7b62ce-9c24-5d81-8d87-22f6e461a62b"
    strings:
        $typelibguid0lo = "1bcfe538-14f4-4beb-9a3f-3f9472794902" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}