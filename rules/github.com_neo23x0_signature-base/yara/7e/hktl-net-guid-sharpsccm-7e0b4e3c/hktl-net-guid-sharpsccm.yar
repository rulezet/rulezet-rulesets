rule HKTL_NET_GUID_SharpSCCM {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/Mayyhem/SharpSCCM"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-15"
        modified = "2025-08-15"
        id = "276269b1-e3b3-5774-a86a-1c3a8bca8209"
    strings:
        $typelibguid0lo = "03652836-898e-4a9f-b781-b7d86e750f60" ascii wide
        $typelibguid1lo = "e4d9ef39-0fce-4573-978b-abf8df6aec23" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}