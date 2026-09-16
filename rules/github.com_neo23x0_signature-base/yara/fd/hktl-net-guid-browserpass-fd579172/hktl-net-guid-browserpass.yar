rule HKTL_NET_GUID_BrowserPass {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/jabiel/BrowserPass"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "bad36c36-dbed-527c-a2f5-4dceff1abe4b"
    strings:
        $typelibguid0lo = "3cb59871-0dce-453b-857a-2d1e515b0b66" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}