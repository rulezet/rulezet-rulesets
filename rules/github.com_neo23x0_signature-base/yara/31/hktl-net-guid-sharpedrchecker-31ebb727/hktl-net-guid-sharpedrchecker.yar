rule HKTL_NET_GUID_SharpEDRChecker {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/PwnDexter/SharpEDRChecker"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-18"
        modified = "2025-08-15"
        id = "f7ff344e-f8ee-5c3a-bdd1-de3cae8e7dfb"
    strings:
        $typelibguid0lo = "bdfee233-3fed-42e5-aa64-492eb2ac7047" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}