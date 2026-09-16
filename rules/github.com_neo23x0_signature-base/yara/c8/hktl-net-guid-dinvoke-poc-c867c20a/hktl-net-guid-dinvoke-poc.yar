rule HKTL_NET_GUID_DInvoke_PoC {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/dtrizna/DInvoke_PoC"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "f3b0ef47-a92c-5c5d-a9e2-09579fcb438e"
    strings:
        $typelibguid0lo = "5a869ab2-291a-49e6-a1b7-0d0f051bef0e" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}