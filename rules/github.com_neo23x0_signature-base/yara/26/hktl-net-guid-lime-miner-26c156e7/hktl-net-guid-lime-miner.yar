rule HKTL_NET_GUID_Lime_Miner {
    meta:
        description = "Detects VB.NET red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/Lime-Miner"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-30"
        modified = "2025-08-15"
        id = "d0631817-10a2-55bf-a41d-226fa0dcb9f9"
    strings:
        $typelibguid0lo = "13958fb9-dfc1-4e2c-8a8d-a5e68abdbc66" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}