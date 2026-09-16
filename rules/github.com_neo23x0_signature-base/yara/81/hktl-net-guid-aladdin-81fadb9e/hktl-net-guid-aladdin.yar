rule HKTL_NET_GUID_Aladdin {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/nettitude/Aladdin"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-13"
        modified = "2025-08-15"
        id = "3f0a954c-f3b3-5e5d-a71d-11f60b026a48"
    strings:
        $typelibguid0lo = "b2b3adb0-1669-4b94-86cb-6dd682ddbea3" ascii wide
        $typelibguid1lo = "c47e4d64-cc7f-490e-8f09-055e009f33ba" ascii wide
        $typelibguid2lo = "32a91b0f-30cd-4c75-be79-ccbd6345de99" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}