rule HKTL_NET_GUID_Gopher {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/EncodeGroup/Gopher"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "e3015719-9085-584d-8237-f377ec995149"
    strings:
        $typelibguid0lo = "b5152683-2514-49ce-9aca-1bc43df1e234" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}