rule HKTL_NET_GUID_SharpKatz {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/b4rtik/SharpKatz"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "ff084b4c-4b00-5504-85ee-d6d17b5be504"
    strings:
        $typelibguid0lo = "8568b4c1-2940-4f6c-bf4e-4383ef268be9" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}