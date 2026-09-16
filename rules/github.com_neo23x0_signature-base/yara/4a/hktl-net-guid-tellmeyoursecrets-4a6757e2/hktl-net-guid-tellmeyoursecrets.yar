rule HKTL_NET_GUID_TellMeYourSecrets {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0xbadjuju/TellMeYourSecrets"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "b00c353b-0446-5faa-87e5-0a7ba6ec2286"
    strings:
        $typelibguid0lo = "9b448062-7219-4d82-9a0a-e784c4b3aa27" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}