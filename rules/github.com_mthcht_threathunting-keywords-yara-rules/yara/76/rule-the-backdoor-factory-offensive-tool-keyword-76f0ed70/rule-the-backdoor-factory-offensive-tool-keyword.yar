rule rule_the_backdoor_factory_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'the-backdoor-factory' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "the-backdoor-factory"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_the_backdoor_factory_offensive_tool_keyword = /\sbackdoor\.py/ nocase ascii wide
                        $string2_the_backdoor_factory_offensive_tool_keyword = /\s\-f\s.{0,100}\.exe\s\-m\sonionduke\s\-b\s.{0,100}\.dll/ nocase ascii wide
                        $string3_the_backdoor_factory_offensive_tool_keyword = /\s\-f\s.{0,100}\.exe\s\-m\sonionduke\s\-b\s.{0,100}\.exe/ nocase ascii wide
                        $string4_the_backdoor_factory_offensive_tool_keyword = /\s\-f\spsexec\.exe\s\-H\s.{0,100}\s\-P\s.{0,100}\s\-s\sreverse_shell_tcp/ nocase ascii wide
                        $string5_the_backdoor_factory_offensive_tool_keyword = /\s\-f\stcpview\.exe\s\-s\siat_reverse_tcp_inline\s\-H\s.{0,100}\s\-P\s.{0,100}\s\-m\sautomatic\s\-C/ nocase ascii wide
                        $string6_the_backdoor_factory_offensive_tool_keyword = /\s\-f\sTeamViewer\.exe\s\-H\s.{0,100}\s\-P\s.{0,100}\s\-s\s/ nocase ascii wide
                        $string7_the_backdoor_factory_offensive_tool_keyword = /\s\-i\s\-H\s.{0,100}\s\-P\s.{0,100}\s\-s\sreverse_shell_tcp\s\-a\s\-u\s\.moocowwow/ nocase ascii wide
                        $string8_the_backdoor_factory_offensive_tool_keyword = " install backdoor-factory" nocase ascii wide
                        $string9_the_backdoor_factory_offensive_tool_keyword = /\spayloadtests\.py/ nocase ascii wide
                        $string10_the_backdoor_factory_offensive_tool_keyword = /\/backdoor\.py/ nocase ascii wide
                        $string11_the_backdoor_factory_offensive_tool_keyword = /\/payloadtests\.py/ nocase ascii wide
                        $string12_the_backdoor_factory_offensive_tool_keyword = /\/the\-backdoor\-factory\.git/ nocase ascii wide
                        $string13_the_backdoor_factory_offensive_tool_keyword = /\\backdoored\\/ nocase ascii wide
                        $string14_the_backdoor_factory_offensive_tool_keyword = /\\payloadtests\.py/ nocase ascii wide
                        $string15_the_backdoor_factory_offensive_tool_keyword = /\\the\-backdoor\-factory\\/ nocase ascii wide
                        $string16_the_backdoor_factory_offensive_tool_keyword = "5b36e42494ab562f7adb9c5dbf17761300050efd24c1c9c61dcb82e5bb628840" nocase ascii wide
                        $string17_the_backdoor_factory_offensive_tool_keyword = "9d0ff36d92bb6cac9255111b4af63700c5e796fe8233504b4acd1ec4f92bb43f" nocase ascii wide
                        $string18_the_backdoor_factory_offensive_tool_keyword = "baf6deb599ee2e6cd817dbc447bdb4ea3cf9a585708c8c585f9a104ffba2b8d9" nocase ascii wide
                        $string19_the_backdoor_factory_offensive_tool_keyword = "d4aae162571f8338f2560eb32b774647fd0f1952d901dd38f8685e42ceeea813" nocase ascii wide
                        $string20_the_backdoor_factory_offensive_tool_keyword = /LinuxARMLELF32\.py/
                        $string21_the_backdoor_factory_offensive_tool_keyword = /loadliba_reverse_tcp\.asm/ nocase ascii wide
                        $string22_the_backdoor_factory_offensive_tool_keyword = /loadliba_shell\.asm/ nocase ascii wide
                        $string23_the_backdoor_factory_offensive_tool_keyword = /loadliba_single_shell_reverse_tcp\.asm/ nocase ascii wide
                        $string24_the_backdoor_factory_offensive_tool_keyword = "secretsquirrel/the-backdoor-factory" nocase ascii wide
                        $string25_the_backdoor_factory_offensive_tool_keyword = "the-backdoor-factory-master" nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}