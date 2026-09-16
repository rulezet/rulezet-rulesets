rule HKTL_NET_GUID_TikiTorch {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rasta-mouse/TikiTorch"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "354ee690-a0d0-5cc5-a73b-53b916ed0169"
    strings:
        $typelibguid0lo = "806c6c72-4adc-43d9-b028-6872fa48d334" ascii wide
        $typelibguid1lo = "2ef9d8f7-6b77-4b75-822b-6a53a922c30f" ascii wide
        $typelibguid2lo = "8f5f3a95-f05c-4dce-8bc3-d0a0d4153db6" ascii wide
        $typelibguid3lo = "1f707405-9708-4a34-a809-2c62b84d4f0a" ascii wide
        $typelibguid4lo = "97421325-b6d8-49e5-adf0-e2126abc17ee" ascii wide
        $typelibguid5lo = "06c247da-e2e1-47f3-bc3c-da0838a6df1f" ascii wide
        $typelibguid6lo = "fc700ac6-5182-421f-8853-0ad18cdbeb39" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}