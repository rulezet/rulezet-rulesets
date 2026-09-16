rule HKTL_NET_NAME_Recon_AD {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/outflanknl/Recon-AD"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
        id = "097de5cd-0cd4-59cc-a7b7-54cad8e6d230"
    strings:
        $name = "Recon-AD" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}