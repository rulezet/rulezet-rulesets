rule HKTL_NET_GUID_SharpOxidResolver {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/S3cur3Th1sSh1t/SharpOxidResolver"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-22"
        modified = "2025-08-15"
        id = "e8a957bc-3319-51c2-8289-01bd0b8a632a"
    strings:
        $typelibguid0lo = "ce59f8ff-0ecf-41e9-a1fd-1776ca0b703d" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}