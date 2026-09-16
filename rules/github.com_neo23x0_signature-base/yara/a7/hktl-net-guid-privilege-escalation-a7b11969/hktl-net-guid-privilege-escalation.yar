rule HKTL_NET_GUID_Privilege_Escalation {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Mrakovic-ORG/Privilege_Escalation"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "28615807-6637-57fc-ba56-efc64b041b80"
    strings:
        $typelibguid0lo = "ed54b904-5645-4830-8e68-52fd9ecbb2eb" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}