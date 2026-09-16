rule HKTL_NET_GUID_DeviceGuardBypasses {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/tyranid/DeviceGuardBypasses"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "3790faac-b5be-5999-b35f-71a2ef02b6ed"
    strings:
        $typelibguid0lo = "f318466d-d310-49ad-a967-67efbba29898" ascii wide
        $typelibguid1lo = "3705800f-1424-465b-937d-586e3a622a4f" ascii wide
        $typelibguid2lo = "256607c2-4126-4272-a2fa-a1ffc0a734f0" ascii wide
        $typelibguid3lo = "4e6ceea1-f266-401c-b832-f91432d46f42" ascii wide
        $typelibguid4lo = "1e6e9b03-dd5f-4047-b386-af7a7904f884" ascii wide
        $typelibguid5lo = "d85e3601-0421-4efa-a479-f3370c0498fd" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}