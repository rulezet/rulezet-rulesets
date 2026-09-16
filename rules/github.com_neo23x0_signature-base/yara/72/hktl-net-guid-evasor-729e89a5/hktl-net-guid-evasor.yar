rule HKTL_NET_GUID_Evasor {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/cyberark/Evasor"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "457959ed-3e90-52c7-89f9-e1b17b35260e"
    strings:
        $typelibguid0lo = "1c8849ef-ad09-4727-bf81-1f777bd1aef8" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}