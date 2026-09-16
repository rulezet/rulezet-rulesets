rule HKTL_NET_GUID_MultiOS_ReverseShell {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/belane/MultiOS_ReverseShell"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "f54bcb1a-b0cd-5988-bf1d-4fa6c012d6b9"
    strings:
        $typelibguid0lo = "df0dd7a1-9f6b-4b0f-801e-e17e73b0801d" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}