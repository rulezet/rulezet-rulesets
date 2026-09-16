rule HKTL_NET_GUID_SharpPack {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Lexus89/SharpPack"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "633d074a-b8c2-5148-ad80-6226b99be818"
    strings:
        $typelibguid1lo = "b59c7741-d522-4a41-bf4d-9badddebb84a" ascii wide
        $typelibguid2lo = "fd6bdf7a-fef4-4b28-9027-5bf750f08048" ascii wide
        $typelibguid3lo = "6dd22880-dac5-4b4d-9c91-8c35cc7b8180" ascii wide
        $typelibguid5lo = "f3037587-1a3b-41f1-aa71-b026efdb2a82" ascii wide
        $typelibguid6lo = "41a90a6a-f9ed-4a2f-8448-d544ec1fd753" ascii wide
        $typelibguid7lo = "3787435b-8352-4bd8-a1c6-e5a1b73921f4" ascii wide
        $typelibguid8lo = "fdd654f5-5c54-4d93-bf8e-faf11b00e3e9" ascii wide
        $typelibguid9lo = "aec32155-d589-4150-8fe7-2900df4554c8" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}