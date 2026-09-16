rule HKTL_NET_GUID_Watson {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rasta-mouse/Watson"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-21"
        modified = "2025-08-15"
        id = "6dc7bb08-0b34-50a0-8ae8-02d96d66a334"
    strings:
        $typelibguid0lo = "49ad5f38-9e37-4967-9e84-fe19c7434ed7" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}