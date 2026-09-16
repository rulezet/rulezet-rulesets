rule HKTL_NET_GUID_Ladon {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/k8gege/Ladon"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "57e3d2fa-d430-561b-9d42-cf58cda5ed7a"
    strings:
        $typelibguid0lo = "c335405f-5df2-4c7d-9b53-d65adfbed412" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}