rule HKTL_NET_GUID_PoshSecFramework {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/PoshSec/PoshSecFramework"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "a91620f3-3f21-525a-bc87-94d21cd126be"
    strings:
        $typelibguid0lo = "b1ac6aa0-2f1a-4696-bf4b-0e41cf2f4b6b" ascii wide
        $typelibguid1lo = "78bfcfc2-ef1c-4514-bce6-934b251666d2" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}