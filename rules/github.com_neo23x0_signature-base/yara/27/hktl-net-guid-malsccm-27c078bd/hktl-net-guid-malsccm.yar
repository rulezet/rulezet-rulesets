rule HKTL_NET_GUID_MalSCCM {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/nettitude/MalSCCM"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-22"
        modified = "2025-08-15"
        id = "4a88532b-e2bc-5ce9-828d-6ef62d91f6b9"
    strings:
        $typelibguid0lo = "5439cecd-3bb3-4807-b33f-e4c299b71ca2" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}