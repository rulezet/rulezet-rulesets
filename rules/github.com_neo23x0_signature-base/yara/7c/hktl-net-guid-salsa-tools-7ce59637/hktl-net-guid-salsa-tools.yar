rule HKTL_NET_GUID_Salsa_tools {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Hackplayers/Salsa-tools"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "50db578e-6ddb-54d1-a978-e3630a3548c3"
    strings:
        $typelibguid0lo = "276004bb-5200-4381-843c-934e4c385b66" ascii wide
        $typelibguid1lo = "cfcbf7b6-1c69-4b1f-8651-6bdb4b55f6b9" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}