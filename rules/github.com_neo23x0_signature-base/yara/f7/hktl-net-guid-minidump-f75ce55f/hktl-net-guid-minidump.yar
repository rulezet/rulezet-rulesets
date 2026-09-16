rule HKTL_NET_GUID_Minidump {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/3xpl01tc0d3r/Minidump"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "51f64c64-f3fa-5543-83fc-5f0bf881ef03"
    strings:
        $typelibguid0lo = "15c241aa-e73c-4b38-9489-9a344ac268a3" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}