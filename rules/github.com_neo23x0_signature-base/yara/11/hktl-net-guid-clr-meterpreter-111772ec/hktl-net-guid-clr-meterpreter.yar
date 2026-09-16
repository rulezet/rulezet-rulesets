rule HKTL_NET_GUID_clr_meterpreter {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/OJ/clr-meterpreter"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "1d8a9717-4d80-5fb1-9c57-9b5f6c5a18b0"
    strings:
        $typelibguid0lo = "6840b249-1a0e-433b-be79-a927696ea4b3" ascii wide
        $typelibguid1lo = "67c09d37-ac18-4f15-8dd6-b5da721c0df6" ascii wide
        $typelibguid2lo = "e05d0deb-d724-4448-8c4c-53d6a8e670f3" ascii wide
        $typelibguid3lo = "c3cc72bf-62a2-4034-af66-e66da73e425d" ascii wide
        $typelibguid4lo = "7ace3762-d8e1-4969-a5a0-dcaf7b18164e" ascii wide
        $typelibguid5lo = "3296e4a3-94b5-4232-b423-44f4c7421cb3" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}