rule HKTL_NET_GUID_PowerShdll {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/p3nt4/PowerShdll"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "3f582a47-078e-525f-9d02-4ee7a455a3b2"
    strings:
        $typelibguid0lo = "36ebf9aa-2f37-4f1d-a2f1-f2a45deeaf21" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}