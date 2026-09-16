rule HKTL_NET_GUID_donut {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/TheWover/donut"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-21"
        modified = "2025-08-15"
        id = "564dfd0a-af9b-505f-a6f0-de2a5c5c63f3"
    strings:
        $typelibguid0lo = "98ca74c7-a074-434d-9772-75896e73ceaa" ascii wide
        $typelibguid1lo = "3c9a6b88-bed2-4ba8-964c-77ec29bf1846" ascii wide
        $typelibguid2lo = "4fcdf3a3-aeef-43ea-9297-0d3bde3bdad2" ascii wide
        $typelibguid3lo = "361c69f5-7885-4931-949a-b91eeab170e3" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}