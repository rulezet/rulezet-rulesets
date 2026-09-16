rule HKTL_NET_GUID_SneakyExec {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/HackingThings/SneakyExec"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "853b630d-77ba-5847-a129-c9fa0538f81b"
    strings:
        $typelibguid0lo = "612590aa-af68-41e6-8ce2-e831f7fe4ccc" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}