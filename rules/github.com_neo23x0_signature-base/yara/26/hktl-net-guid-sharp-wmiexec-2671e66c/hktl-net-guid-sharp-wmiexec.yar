rule HKTL_NET_GUID_Sharp_WMIExec {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/checkymander/Sharp-WMIExec"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "ae08a5a2-06d5-55fe-803a-7f4696220904"
    strings:
        $typelibguid0lo = "0a63b0a1-7d1a-4b84-81c3-bbbfe9913029" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}