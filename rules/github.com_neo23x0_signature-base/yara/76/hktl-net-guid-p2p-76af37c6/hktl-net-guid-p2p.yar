rule HKTL_NET_GUID_p2p {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid (p2p Remote Desktop is dual use but 100% flagged as malicious on VT)"
        reference = "https://github.com/miroslavpejic85/p2p"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-19"
        modified = "2025-08-15"
        id = "e7b2b4bd-f1e1-5062-9b36-5df44ae374ea"
    strings:
        $typelibguid0lo = "33456e72-f8e8-4384-88c4-700867df12e2" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}