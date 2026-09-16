rule HKTL_NET_GUID_AggressorScripts {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/harleyQu1nn/AggressorScripts"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "d5903db5-010b-5b9d-8a5b-5d61aec52e7a"
    strings:
        $typelibguid0lo = "afd1ff09-2632-4087-a30c-43591f32e4e8" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}