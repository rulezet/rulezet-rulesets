rule HKTL_NET_GUID_iSpyKeylogger {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/mwsrc/iSpyKeylogger"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "8607de67-b472-5afc-b2b9-cc758b5ec474"
    strings:
        $typelibguid0lo = "ccc0a386-c4ce-42ef-aaea-b2af7eff4ad8" ascii wide
        $typelibguid1lo = "816b8b90-2975-46d3-aac9-3c45b26437fa" ascii wide
        $typelibguid2lo = "279b5533-d3ac-438f-ba89-3fe9de2da263" ascii wide
        $typelibguid3lo = "88d3dc02-2853-4bf0-b6dc-ad31f5135d26" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}