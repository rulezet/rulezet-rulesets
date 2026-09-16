rule HKTL_NET_GUID_GadgetToJScript {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/med0x2e/GadgetToJScript"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "e296795f-d006-52a9-92c4-fb60c930564b"
    strings:
        $typelibguid0lo = "af9c62a1-f8d2-4be0-b019-0a7873e81ea9" ascii wide
        $typelibguid1lo = "b2b3adb0-1669-4b94-86cb-6dd682ddbea3" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}