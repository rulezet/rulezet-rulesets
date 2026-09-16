rule HKTL_NET_GUID_SharpShell {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/cobbr/SharpShell"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "5966be44-c010-5c63-9576-1aaf36397d6c"
    strings:
        $typelibguid0lo = "bdba47c5-e823-4404-91d0-7f6561279525" ascii wide
        $typelibguid1lo = "b84548dc-d926-4b39-8293-fa0bdef34d49" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}