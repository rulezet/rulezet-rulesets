rule HKTL_NET_GUID_StormKitty {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/LimerBoy/StormKitty"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "09d66661-5b67-5846-9bea-ec682afb62cf"
    strings:
        $typelibguid0lo = "a16abbb4-985b-4db2-a80c-21268b26c73d" ascii wide
        $typelibguid1lo = "98075331-1f86-48c8-ae29-29da39a8f98b" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}