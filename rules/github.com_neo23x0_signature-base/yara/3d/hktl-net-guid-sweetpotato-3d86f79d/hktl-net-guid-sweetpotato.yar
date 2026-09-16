rule HKTL_NET_GUID_SweetPotato {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/CCob/SweetPotato"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "0e347d94-51eb-5589-93d8-b19fec7f2365"
    strings:
        $typelibguid0lo = "6aeb5004-6093-4c23-aeae-911d64cacc58" ascii wide
        $typelibguid1lo = "1bf9c10f-6f89-4520-9d2e-aaf17d17ba5e" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}