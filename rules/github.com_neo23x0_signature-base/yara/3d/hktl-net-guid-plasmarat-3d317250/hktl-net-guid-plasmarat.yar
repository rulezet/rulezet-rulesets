rule HKTL_NET_GUID_PlasmaRAT {
    meta:
        description = "Detects VB.NET red/black-team tools via typelibguid"
        reference = "https://github.com/mwsrc/PlasmaRAT"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-30"
        modified = "2025-08-15"
        id = "13362cba-f9b2-50c8-95cc-504e585bdd42"
    strings:
        $typelibguid0lo = "b8a2147c-074c-46e1-bb99-c8431a6546ce" ascii wide
        $typelibguid1lo = "0fcfde33-213f-4fb6-ac15-efb20393d4f3" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}