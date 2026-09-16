rule HKTL_NET_GUID_SharpNamedPipePTH {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/S3cur3Th1sSh1t/SharpNamedPipePTH"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-11-30"
        id = "561b95a5-f32b-5fe8-9e67-3f702306be93"
    strings:
        $typelibguid0 = "344ee55a-4e32-46f2-a003-69ad52b55945" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}