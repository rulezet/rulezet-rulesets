rule HKTL_NET_GUID_AmsiScanBufferBypass {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rasta-mouse/AmsiScanBufferBypass"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "12a15e61-30fb-50a3-a59b-39f9871444f0"
    strings:
        $typelibguid0lo = "431ef2d9-5cca-41d3-87ba-c7f5e4582dd2" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}