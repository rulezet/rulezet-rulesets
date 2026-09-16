rule HKTL_NET_GUID_SharpAttack {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/jaredhaight/SharpAttack"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "1eb911ab-3fb9-54b7-8afb-66328f30d563"
    strings:
        $typelibguid0lo = "5f0ceca3-5997-406c-adf5-6c7fbb6cba17" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}