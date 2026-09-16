rule HKTL_NET_NAME_gray_hat_csharp_code {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/brandonprry/gray_hat_csharp_code"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2021-01-22"
        id = "0a94cadc-cc7b-5817-8788-bb1e53937fad"
    strings:
        $name = "gray_hat_csharp_code" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}