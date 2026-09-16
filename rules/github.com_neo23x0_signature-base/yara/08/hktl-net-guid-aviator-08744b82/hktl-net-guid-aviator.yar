rule HKTL_NET_GUID_AVIator {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Ch0pin/AVIator"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "52acd520-52aa-5bb9-ab3b-66a940aa5f5a"
    strings:
        $typelibguid0lo = "4885a4a3-4dfa-486c-b378-ae94a221661a" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}