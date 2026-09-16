rule rule_chaos_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'chaos' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "chaos"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_chaos_offensive_tool_keyword = /\schaos\.exe\s/ nocase ascii wide
                        $string2_chaos_offensive_tool_keyword = " SQLITE_DATABASE=chaos " nocase ascii wide
                        $string3_chaos_offensive_tool_keyword = " SQLITE_DATABASE=chaos" nocase ascii wide
                        $string4_chaos_offensive_tool_keyword = /\/CHAOS\.git/ nocase ascii wide
                        $string5_chaos_offensive_tool_keyword = /\/CHAOS\-5\.0\.1\.zip/ nocase ascii wide
                        $string6_chaos_offensive_tool_keyword = "/chaos-container:/database/" nocase ascii wide
                        $string7_chaos_offensive_tool_keyword = /\\chaos\.exe/ nocase ascii wide
                        $string8_chaos_offensive_tool_keyword = /\\CHAOS\-5\.0\.1\.zip/ nocase ascii wide
                        $string9_chaos_offensive_tool_keyword = /\\CHAOS\-master\.zip/ nocase ascii wide
                        $string10_chaos_offensive_tool_keyword = "3ec15909c169e37f1173d567cb4729f592002826ac0a0f5bf5e820af47195e78" nocase ascii wide
                        $string11_chaos_offensive_tool_keyword = "401ab31450e32d265a189983c56a0f7f947b15fe3559c08773275f6c1e6625ce" nocase ascii wide
                        $string12_chaos_offensive_tool_keyword = "48a61f194676d3b3f1aef3410eabda1ab57448f1966a91a2d1be5af02a2c77c8" nocase ascii wide
                        $string13_chaos_offensive_tool_keyword = "630cf7ac06f7286e926cfaf1b2ca5105a7caaee6627837da5f71d5b44302f992" nocase ascii wide
                        $string14_chaos_offensive_tool_keyword = "7c4650646cf661efd5ad7dc45f6237f6aa0cc28e81163ce1e3a7b86841cbd5f8" nocase ascii wide
                        $string15_chaos_offensive_tool_keyword = "7f994093b3133e5450cd89d4a9cc39cceca8bbcce8845665f86b4d7eb9998d61" nocase ascii wide
                        $string16_chaos_offensive_tool_keyword = "bfca678c800832025fe5e7c59bdf9bc3a2a62c77e7b689b943fee2821c2fec19" nocase ascii wide
                        $string17_chaos_offensive_tool_keyword = "c:/chaos-container:/database/" nocase ascii wide
                        $string18_chaos_offensive_tool_keyword = /C\:\\Users\\.{0,100}\\AppData\\Roaming\\svchost\.exe/ nocase ascii wide
                        $string19_chaos_offensive_tool_keyword = /CHAOS\s\(Remote\sAdministration\sTool\)/ nocase ascii wide
                        $string20_chaos_offensive_tool_keyword = /chaos.{0,100}persistence_enable/ nocase ascii wide
                        $string21_chaos_offensive_tool_keyword = /docker.{0,100}\/chaos\-container\:\/temp\// nocase ascii wide
                        $string22_chaos_offensive_tool_keyword = "ec2a250f026c030d36c1f1d021816176a7a9a8f62f56673b418bca9154c5a3f1" nocase ascii wide
                        $string23_chaos_offensive_tool_keyword = /go\srun\scmd\/chaos\/main\.go/ nocase ascii wide
                        $string24_chaos_offensive_tool_keyword = /md\sc\:\\chaos\-container/ nocase ascii wide
                        $string25_chaos_offensive_tool_keyword = "tiagorlampert/CHAOS" nocase ascii wide
                        $string26_chaos_offensive_tool_keyword = "tiagorlampert/chaos:latest" nocase ascii wide
                        $string27_chaos_offensive_tool_keyword = /tiagorlampert\@gmail\.com/ nocase ascii wide
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