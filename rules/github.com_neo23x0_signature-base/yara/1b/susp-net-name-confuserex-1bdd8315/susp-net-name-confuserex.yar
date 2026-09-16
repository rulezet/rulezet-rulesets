rule SUSP_NET_NAME_ConfuserEx {
    meta:
        description = "Detects ConfuserEx packed file"
        reference = "https://github.com/yck1509/ConfuserEx"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        score = 40
        date = "2021-01-22"
        modified = "2021-01-25"
        id = "f1bda14e-c9fe-5341-8962-691a66233eb0"
    strings:
        $name = "ConfuserEx" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}