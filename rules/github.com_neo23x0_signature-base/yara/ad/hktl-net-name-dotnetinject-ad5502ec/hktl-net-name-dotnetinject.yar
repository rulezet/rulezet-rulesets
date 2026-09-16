rule HKTL_NET_NAME_DotNetInject {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/dtrizna/DotNetInject"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
        modified = "2022-06-28"
        id = "468f89c4-5b94-53be-b9e6-ad21de7d98ba"
    strings:
        $name = "DotNetInject" ascii wide
        $compile = "AssemblyTitle" ascii wide

        $fp1 = "GetDotNetInjector" ascii 
        $fp2 = "JetBrains.TeamCity.Injector." wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550)
        and filesize < 20MB
        and $name and $compile
        and not 1 of ($fp*)
}