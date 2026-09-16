rule rule_Arbitrium_RAT_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Arbitrium-RAT' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Arbitrium-RAT"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Arbitrium_RAT_offensive_tool_keyword = /\sa\s\-r\s\-cfg\s\-sfx\s\-z\\"SFXAutoInstaller\.conf\\"\sStandalone\.exe/
                        $string2_Arbitrium_RAT_offensive_tool_keyword = /\/Arbitrium\-RAT\.git/ nocase ascii wide
                        $string3_Arbitrium_RAT_offensive_tool_keyword = /\[\+\]\sthe\sArbitrium\-Server\sis\srunning/ nocase ascii wide
                        $string4_Arbitrium_RAT_offensive_tool_keyword = "2437b5db59dd1b987232c3f0b4ed53408bce886e98e879887d3a1c52ee93e141" nocase ascii wide
                        $string5_Arbitrium_RAT_offensive_tool_keyword = "2aa4f05b7acf28440538a3295d015e9dbbb919730d225e6b2f1051e328f6b3c4" nocase ascii wide
                        $string6_Arbitrium_RAT_offensive_tool_keyword = "3aafc3d5f312ebd5b34219e53e22592f82b039fffe70322982a03a498c604d3a" nocase ascii wide
                        $string7_Arbitrium_RAT_offensive_tool_keyword = "55bb7968642a55819b608e5e2e732982424b6f47e5ef774a0a35dff202f6321f" nocase ascii wide
                        $string8_Arbitrium_RAT_offensive_tool_keyword = "5cf784da346a55c15259f755ffc19790a90cd616449a47bb9617cf93bfe91441" nocase ascii wide
                        $string9_Arbitrium_RAT_offensive_tool_keyword = "78656dcbb5b795a7e71947b0f45fc054ced091ee2b62a41562879750ff111200" nocase ascii wide
                        $string10_Arbitrium_RAT_offensive_tool_keyword = "9eb78bef9bba6135087de0c8307c2f893eef9a4a2d1f8c37de643f059ce2f711" nocase ascii wide
                        $string11_Arbitrium_RAT_offensive_tool_keyword = "a976cdbaf7401fcf1de10254a4db2873b1b4c8c0b6f0e45a51978e3c77a6968a" nocase ascii wide
                        $string12_Arbitrium_RAT_offensive_tool_keyword = "c5ce3e817030e3bd925c09fcd3eaacf4705dfaacad9bdec485a4f246eb726a81" nocase ascii wide
                        $string13_Arbitrium_RAT_offensive_tool_keyword = /cmd\.exe\s\/c\s\\"OK\!\\"/ nocase ascii wide
                        $string14_Arbitrium_RAT_offensive_tool_keyword = "d3eb242554adec76ed43cb76dae2c776bf086b2e2c15335c80fe79852286310e" nocase ascii wide
                        $string15_Arbitrium_RAT_offensive_tool_keyword = "e8fbec25db4f9d95b5e8f41cca51a4b32be8674a4dea7a45b6f7aeb22dbc38db" nocase ascii wide
                        $string16_Arbitrium_RAT_offensive_tool_keyword = "e8fbec25db4f9d95b5e8f41cca51a4b32be8674a4dea7a45b6f7aeb22dbc38db" nocase ascii wide
                        $string17_Arbitrium_RAT_offensive_tool_keyword = /http\:\/\/bit\.ly\/1qMn59d/ nocase ascii wide
                        $string18_Arbitrium_RAT_offensive_tool_keyword = "im-hanzou/Arbitrium-RAT" nocase ascii wide
                        $string19_Arbitrium_RAT_offensive_tool_keyword = /mimikatz\.py/ nocase ascii wide
                        $string20_Arbitrium_RAT_offensive_tool_keyword = /New\-Object\sNet\.WebClient\)\.DownloadString.{0,100}\s\-DumpCreds/ nocase ascii wide
                        $string21_Arbitrium_RAT_offensive_tool_keyword = /pip\sinstall\sflask\sflask_cors\s\&\&\s\.\/runserver\.sh/
                        $string22_Arbitrium_RAT_offensive_tool_keyword = /Popen\(\\"exec\s\$\(nc\s\-l\s0\.0\.0\.0\s\-p\s/ nocase ascii wide
                        $string23_Arbitrium_RAT_offensive_tool_keyword = /python\sreverse_http\.py/ nocase ascii wide
                        $string24_Arbitrium_RAT_offensive_tool_keyword = "User-Agent: JustKidding" nocase ascii wide
                        $string25_Arbitrium_RAT_offensive_tool_keyword = "'User-Agent': 'JustKidding'" nocase ascii wide
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