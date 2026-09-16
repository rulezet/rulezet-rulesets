rule HKTL_NET_GUID_PortTran {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/k8gege/PortTran"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-29"
        modified = "2025-08-15"
        id = "844e58a2-54f5-51e8-8176-6a478a136603"
    strings:
        $typelibguid0lo = "3a074374-77e8-4312-8746-37f3cb00e82c" ascii wide
        $typelibguid1lo = "67a73bac-f59d-4227-9220-e20a2ef42782" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}