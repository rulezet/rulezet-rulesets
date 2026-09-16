rule HKTL_NET_GUID_CasperStager {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/ustayready/CasperStager"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "0ad18d2b-b7cc-5316-a8e8-b05d4439b8e1"
    strings:
        $typelibguid0lo = "c653a9f2-0939-43c8-9b93-fed5e2e4c7e6" ascii wide
        $typelibguid1lo = "48dfc55e-6ae5-4a36-abef-14bc09d7510b" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}