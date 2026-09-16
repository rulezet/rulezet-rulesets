rule HKTL_NET_GUID_Random_CSharpTools {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/xorrior/Random-CSharpTools"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-21"
        modified = "2025-08-15"
        id = "ad8b5573-ad20-50cd-927b-a6401b10e653"
    strings:
        $typelibguid0lo = "f7fc19da-67a3-437d-b3b0-2a257f77a00b" ascii wide
        $typelibguid1lo = "47e85bb6-9138-4374-8092-0aeb301fe64b" ascii wide
        $typelibguid2lo = "c7d854d8-4e3a-43a6-872f-e0710e5943f7" ascii wide
        $typelibguid3lo = "d6685430-8d8d-4e2e-b202-de14efa25211" ascii wide
        $typelibguid4lo = "1df925fc-9a89-4170-b763-1c735430b7d0" ascii wide
        $typelibguid5lo = "817cc61b-8471-4c1e-b5d6-c754fc550a03" ascii wide
        $typelibguid6lo = "60116613-c74e-41b9-b80e-35e02f25891e" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}