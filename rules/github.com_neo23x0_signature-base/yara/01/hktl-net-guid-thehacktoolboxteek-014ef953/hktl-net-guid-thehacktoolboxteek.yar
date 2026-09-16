rule HKTL_NET_GUID_TheHackToolBoxTeek {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/teeknofil/TheHackToolBoxTeek"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "ad8cf2c8-f70e-5f46-92fa-46e1fa5e683c"
    strings:
        $typelibguid0lo = "2aa8c254-b3b3-469c-b0c9-dcbe1dd101c0" ascii wide
        $typelibguid1lo = "afeff505-14c1-4ecf-b714-abac4fbd48e7" ascii wide
        $typelibguid2lo = "4cf42167-a5cf-4b2d-85b4-8e764c08d6b3" ascii wide
        $typelibguid3lo = "118a90b7-598a-4cfc-859e-8013c8b9339c" ascii wide
        $typelibguid4lo = "3075dd9a-4283-4d38-a25e-9f9845e5adcb" ascii wide
        $typelibguid5lo = "295655e8-2348-4700-9ebc-aa57df54887e" ascii wide
        $typelibguid6lo = "74efe601-9a93-46c3-932e-b80ab6570e42" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}