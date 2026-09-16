rule HKTL_NET_GUID_POSTDump {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/YOLOP0wn/POSTDump"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-12-19"
        id = "7f33e76c-0227-5c23-b821-c5c9753e2384"
    strings:
        $typelibguid0 = "e54195f0-060c-4b24-98f2-ad9fb5351045" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}