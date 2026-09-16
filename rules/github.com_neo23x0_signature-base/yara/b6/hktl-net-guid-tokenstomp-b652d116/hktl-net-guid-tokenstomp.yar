rule HKTL_NET_GUID_TokenStomp {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/MartinIngesen/TokenStomp"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2022-11-21"
        modified = "2025-08-15"
        id = "e4266969-ab03-50dc-b5b1-f4bb1c9846f4"
    strings:
        $typelibguid0lo = "8aac271f-9b0b-4dc3-8aa6-812bb7a57e7b" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}