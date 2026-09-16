rule HKTL_NET_GUID_SharpExec {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/anthemtotheego/SharpExec"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "5faff0aa-9ffe-5ac0-b9e0-ca9f79350036"
    strings:
        $typelibguid0lo = "7fbad126-e21c-4c4e-a9f0-613fcf585a71" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}