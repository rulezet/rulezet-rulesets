rule HKTL_NET_GUID_KeeThief {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/GhostPack/KeeThief"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2025-08-15"
        id = "71fef0e9-223a-5834-9d1c-f3fb8b66a809"
    strings:
        $typelibguid1lo = "39aa6f93-a1c9-497f-bad2-cc42a61d5710" ascii wide
        $typelibguid3lo = "3fca8012-3bad-41e4-91f4-534aa9a44f96" ascii wide
        $typelibguid4lo = "ea92f1e6-3f34-48f8-8b0a-f2bbc19220ef" ascii wide
        $typelibguid5lo = "c23b51c4-2475-4fc6-9b3a-27d0a2b99b0f" ascii wide
         
        $typelibguid7lo = "80ba63a4-7d41-40e9-a722-6dd58b28bf7e" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}