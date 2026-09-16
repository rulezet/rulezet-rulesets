rule HKTL_NET_GUID_Misc_CSharp {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/jnqpblc/Misc-CSharp"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-13"
        modified = "2025-08-15"
        id = "d25fa706-2254-5a82-a961-f57a0daa447c"
    strings:
        $typelibguid0lo = "d1421ba3-c60b-42a0-98f9-92ba4e653f3d" ascii wide
        $typelibguid1lo = "2afac0dd-f46f-4f95-8a93-dc17b4f9a3a1" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}