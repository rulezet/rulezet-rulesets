rule HKTL_NET_GUID_CSharpSetThreadContext {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/djhohnstein/CSharpSetThreadContext"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "883bb859-d5ab-501d-8c83-0c5a2cf1f6c8"
    strings:
        $typelibguid0lo = "a1e28c8c-b3bd-44de-85b9-8aa7c18a714d" ascii wide
        $typelibguid1lo = "87c5970e-0c77-4182-afe2-3fe96f785ebb" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}