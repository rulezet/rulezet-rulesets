rule HKTL_NET_GUID_rat_shell {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/stphivos/rat-shell"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "8f206175-f7e4-5543-8059-24f102fcd4b9"
    strings:
        $typelibguid0lo = "7a15f8f6-6ce2-4ca4-919d-2056b70cc76a" ascii wide
        $typelibguid1lo = "1659d65d-93a8-4bae-97d5-66d738fc6f6c" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}