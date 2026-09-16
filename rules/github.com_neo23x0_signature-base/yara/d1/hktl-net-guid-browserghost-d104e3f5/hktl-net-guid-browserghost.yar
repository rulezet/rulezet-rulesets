import "pe"
rule HKTL_NET_GUID_BrowserGhost {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/QAX-A-Team/BrowserGhost"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        modified = "2025-08-15"
        id = "adcc5d12-c393-5708-ae0b-a85f2187c881"
    strings:
        $typelibguid0lo = "2133c634-4139-466e-8983-9a23ec99e01b" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
        and not pe.is_dll()
}