rule HKTL_NET_GUID_AESShellCodeInjector {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/san3ncrypt3d/AESShellCodeInjector"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-22"
        modified = "2025-08-15"
        id = "6253e30b-7c92-5237-a706-e93403a7c0b6"
    strings:
        $typelibguid0lo = "b016da9e-12a1-4f1d-91a1-d681ae54e92c" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}