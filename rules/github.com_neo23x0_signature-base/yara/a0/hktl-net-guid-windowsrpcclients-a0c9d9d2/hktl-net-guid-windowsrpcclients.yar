rule HKTL_NET_GUID_WindowsRpcClients {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/tyranid/WindowsRpcClients"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "70fd7431-8c32-52a4-be9f-2a19ef77f2cc"
    strings:
        $typelibguid0lo = "843d8862-42eb-49ee-94e6-bca798dd33ea" ascii wide
        $typelibguid1lo = "632e4c3b-3013-46fc-bc6e-22828bf629e3" ascii wide
        $typelibguid2lo = "a2091d2f-6f7e-4118-a203-4cea4bea6bfa" ascii wide
        $typelibguid3lo = "950ef8ce-ec92-4e02-b122-0d41d83065b8" ascii wide
        $typelibguid4lo = "d51301bc-31aa-4475-8944-882ecf80e10d" ascii wide
        $typelibguid5lo = "823ff111-4de2-4637-af01-4bdc3ca4cf15" ascii wide
        $typelibguid6lo = "5d28f15e-3bb8-4088-abe0-b517b31d4595" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}