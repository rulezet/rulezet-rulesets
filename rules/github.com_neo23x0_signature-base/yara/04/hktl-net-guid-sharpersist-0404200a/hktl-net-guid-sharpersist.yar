rule HKTL_NET_GUID_SharPersist {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/fireeye/SharPersist"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "0c181186-7bb4-502b-8937-60cfd88ce689"
    strings:
        $typelibguid0lo = "9d1b853e-58f1-4ba5-aefc-5c221ca30e48" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}