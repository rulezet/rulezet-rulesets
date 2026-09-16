rule HKTL_NET_GUID_UnstoppableService {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/malcomvetter/UnstoppableService"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "8c65fbee-d779-57a8-851b-7583be66c67a"
    strings:
        $typelibguid0lo = "0c117ee5-2a21-dead-beef-8cc7f0caaa86" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}