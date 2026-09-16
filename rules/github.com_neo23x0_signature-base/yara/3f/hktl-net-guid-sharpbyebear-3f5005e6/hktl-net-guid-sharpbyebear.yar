rule HKTL_NET_GUID_SharpByeBear {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/S3cur3Th1sSh1t/SharpByeBear"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2025-08-15"
        id = "4a7f2514-2519-5fd5-9d17-110a67f829e7"
    strings:
        $typelibguid0lo = "a6b84e35-2112-4df2-a31b-50fde4458c5e" ascii wide
        $typelibguid1lo = "3e82f538-6336-4fff-aeec-e774676205da" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}