rule HKTL_NET_GUID_PoshC2_Misc {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/nettitude/PoshC2_Misc"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "245803cb-63d8-5c75-b672-912091cf4a80"
    strings:
        $typelibguid0lo = "85773eb7-b159-45fe-96cd-11bad51da6de" ascii wide
        $typelibguid1lo = "9d32ad59-4093-420d-b45c-5fff391e990d" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}