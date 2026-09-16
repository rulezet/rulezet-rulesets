rule HKTL_NET_GUID_AsyncRAT_C_Sharp {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "858a079d-71e8-516e-a2a9-f0969edc758b"
    strings:
        $typelibguid0lo = "619b7612-dfea-442a-a927-d997f99c497b" ascii wide
        $typelibguid1lo = "424b81be-2fac-419f-b4bc-00ccbe38491f" ascii wide
        $typelibguid2lo = "37e20baf-3577-4cd9-bb39-18675854e255" ascii wide
        $typelibguid3lo = "dafe686a-461b-402b-bbd7-2a2f4c87c773" ascii wide
        $typelibguid4lo = "ee03faa9-c9e8-4766-bd4e-5cd54c7f13d3" ascii wide
        $typelibguid5lo = "8bfc8ed2-71cc-49dc-9020-2c8199bc27b6" ascii wide
        $typelibguid6lo = "d640c36b-2c66-449b-a145-eb98322a67c8" ascii wide
        $typelibguid7lo = "8de42da3-be99-4e7e-a3d2-3f65e7c1abce" ascii wide
        $typelibguid8lo = "bee88186-769a-452c-9dd9-d0e0815d92bf" ascii wide
        $typelibguid9lo = "9042b543-13d1-42b3-a5b6-5cc9ad55e150" ascii wide
        $typelibguid10lo = "6aa4e392-aaaf-4408-b550-85863dd4baaf" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}