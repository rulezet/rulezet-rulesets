rule HKTL_NET_GUID_ESC {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NetSPI/ESC"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "a57c47e8-62bf-5425-9735-35a3e3a0c218"
    strings:
        $typelibguid0lo = "06260ce5-61f4-4b81-ad83-7d01c3b37921" ascii wide
        $typelibguid1lo = "87fc7ede-4dae-4f00-ac77-9c40803e8248" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}