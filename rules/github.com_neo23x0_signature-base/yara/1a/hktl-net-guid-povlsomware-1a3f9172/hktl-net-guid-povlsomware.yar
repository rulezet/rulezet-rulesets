rule HKTL_NET_GUID_Povlsomware {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/povlteksttv/Povlsomware"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "0eba43d2-b415-5e72-9677-4a3238ff7c34"
    strings:
        $typelibguid0lo = "fe0d5aa7-538f-42f6-9ece-b141560f7781" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}