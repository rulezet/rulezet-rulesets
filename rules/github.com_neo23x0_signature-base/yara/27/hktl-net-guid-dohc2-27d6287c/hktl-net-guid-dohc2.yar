rule HKTL_NET_GUID_DoHC2 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/SpiderLabs/DoHC2"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "0bb38f10-ca5c-5c18-97c9-540b6367d150"
    strings:
        $typelibguid0lo = "9877a948-2142-4094-98de-e0fbb1bc4062" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}