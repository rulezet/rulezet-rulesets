rule HKTL_NET_GUID_Obfuscator {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/3xpl01tc0d3r/Obfuscator"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "d9988b00-1f10-5421-8ffe-49849a5d5902"
    strings:
        $typelibguid0lo = "8fe5b811-a2cb-417f-af93-6a3cf6650af1" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}