rule HKTL_NET_NAME_MagentoScanner {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/soufianetahiri/MagentoScanner"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
        id = "db3912bd-574c-57e2-a9b6-4b440d144471"
    strings:
        $name = "MagentoScanner" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}