rule HKTL_NET_NAME_WMIPersistence {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/mdsecactivebreach/WMIPersistence"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
        id = "7a674596-c697-569d-a16c-3cefe4ff752a"
    strings:
        $name = "WMIPersistence" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}