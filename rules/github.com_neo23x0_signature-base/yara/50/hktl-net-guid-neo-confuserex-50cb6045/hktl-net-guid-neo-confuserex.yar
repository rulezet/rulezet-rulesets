rule HKTL_NET_GUID_neo_ConfuserEx {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/XenocodeRCE/neo-ConfuserEx"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2025-08-15"
        id = "d73117a6-4512-5545-a4f4-72d8cf708340"
    strings:
        $typelibguid0lo = "e98490bb-63e5-492d-b14e-304de928f81a" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}