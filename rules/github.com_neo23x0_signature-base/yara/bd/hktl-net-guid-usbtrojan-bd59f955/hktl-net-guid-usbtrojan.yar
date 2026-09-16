rule HKTL_NET_GUID_USBTrojan {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/mashed-potatoes/USBTrojan"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "d25c9033-13e8-5fc9-8561-f8862cca39b8"
    strings:
        $typelibguid0lo = "4eee900e-adc5-46a7-8d7d-873fd6aea83e" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}