rule HKTL_NET_GUID_dotnet_gargoyle {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/countercept/dotnet-gargoyle"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "5efd0c83-cb65-5bda-b55e-4a89db5f337c"
    strings:
        $typelibguid0lo = "76435f79-f8af-4d74-8df5-d598a551b895" ascii wide
        $typelibguid1lo = "5a3fc840-5432-4925-b5bc-abc536429cb5" ascii wide
        $typelibguid2lo = "6f0bbb2a-e200-4d76-b8fa-f93c801ac220" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}