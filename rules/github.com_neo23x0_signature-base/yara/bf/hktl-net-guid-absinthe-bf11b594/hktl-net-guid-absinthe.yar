rule HKTL_NET_GUID_Absinthe {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/cameronhotchkies/Absinthe"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-21"
        modified = "2025-08-15"
        id = "8f25593b-b9d2-5807-b299-b039ecfd43a5"
    strings:
        $typelibguid0lo = "9936ae73-fb4e-4c5e-a5fb-f8aaeb3b9bd6" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}