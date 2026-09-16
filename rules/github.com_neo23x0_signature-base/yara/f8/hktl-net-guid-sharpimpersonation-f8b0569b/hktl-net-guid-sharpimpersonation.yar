rule HKTL_NET_GUID_SharpImpersonation {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/S3cur3Th1sSh1t/SharpImpersonation"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-22"
        modified = "2025-08-15"
        id = "5815c5bd-e3e8-5f2f-b03e-8a05fb4f6e91"
    strings:
        $typelibguid0lo = "27a85262-8c87-4147-a908-46728ab7fc73" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}