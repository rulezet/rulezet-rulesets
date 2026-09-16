rule HKTL_NET_GUID_AzureCLI_Extractor {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0x09AL/AzureCLI-Extractor"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "f595545a-a7a6-577c-b3f4-febf7bf1b6c3"
    strings:
        $typelibguid0lo = "a73cad74-f8d6-43e6-9a4c-b87832cdeace" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}