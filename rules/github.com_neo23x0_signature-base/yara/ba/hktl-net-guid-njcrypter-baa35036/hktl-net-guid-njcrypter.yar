rule HKTL_NET_GUID_njCrypter {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0xPh0enix/njCrypter"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "c30c8323-9418-521a-a4fc-6be0113b99b5"
    strings:
        $typelibguid0lo = "8a87b003-4b43-467b-a509-0c8be05bf5a5" ascii wide
        $typelibguid1lo = "80b13bff-24a5-4193-8e51-c62a414060ec" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}