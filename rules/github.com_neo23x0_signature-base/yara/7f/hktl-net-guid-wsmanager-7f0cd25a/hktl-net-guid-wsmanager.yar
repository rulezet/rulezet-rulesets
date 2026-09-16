rule HKTL_NET_GUID_wsManager {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/guillaC/wsManager"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "b8c330dc-74aa-5a33-8af6-17c9beb8be81"
    strings:
        $typelibguid0lo = "9480809e-5472-44f3-b076-dcdf7379e766" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}