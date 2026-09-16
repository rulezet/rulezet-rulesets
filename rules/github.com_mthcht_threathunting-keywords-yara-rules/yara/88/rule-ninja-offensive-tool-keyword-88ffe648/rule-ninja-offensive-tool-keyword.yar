rule rule_Ninja_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Ninja' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Ninja"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Ninja_offensive_tool_keyword = /\sNinja\.py/ nocase ascii wide
                        $string2_Ninja_offensive_tool_keyword = /\sstart_campaign\.py/ nocase ascii wide
                        $string3_Ninja_offensive_tool_keyword = /\.\/Ninja\.py/
                        $string4_Ninja_offensive_tool_keyword = "/ahmedkhlief/Ninja/" nocase ascii wide
                        $string5_Ninja_offensive_tool_keyword = /\/ninja\.crt/ nocase ascii wide
                        $string6_Ninja_offensive_tool_keyword = /\/Ninja\.git/ nocase ascii wide
                        $string7_Ninja_offensive_tool_keyword = /\/ninja\.key/ nocase ascii wide
                        $string8_Ninja_offensive_tool_keyword = /\/Ninja\.py/ nocase ascii wide
                        $string9_Ninja_offensive_tool_keyword = "/opt/Ninja/" nocase ascii wide
                        $string10_Ninja_offensive_tool_keyword = /\/payload2\.ps1/ nocase ascii wide
                        $string11_Ninja_offensive_tool_keyword = /\/start_campaign\.py/ nocase ascii wide
                        $string12_Ninja_offensive_tool_keyword = /\/webshell\.py/ nocase ascii wide
                        $string13_Ninja_offensive_tool_keyword = /\\Ninja\.py/ nocase ascii wide
                        $string14_Ninja_offensive_tool_keyword = /\\start_campaign\.py/ nocase ascii wide
                        $string15_Ninja_offensive_tool_keyword = "agents/Follina-2" nocase ascii wide
                        $string16_Ninja_offensive_tool_keyword = "ahmedkhlief/Ninja" nocase ascii wide
                        $string17_Ninja_offensive_tool_keyword = /AMSI_Bypass\.ps1/ nocase ascii wide
                        $string18_Ninja_offensive_tool_keyword = /ASBBypass\.ps1/ nocase ascii wide
                        $string19_Ninja_offensive_tool_keyword = "b64stager" nocase ascii wide
                        $string20_Ninja_offensive_tool_keyword = "'C2Default'" nocase ascii wide
                        $string21_Ninja_offensive_tool_keyword = /c2\-logs\.txt/ nocase ascii wide
                        $string22_Ninja_offensive_tool_keyword = /cmd_shellcodex64\./ nocase ascii wide
                        $string23_Ninja_offensive_tool_keyword = /cmd_shellcodex86\./ nocase ascii wide
                        $string24_Ninja_offensive_tool_keyword = /create\-aws\-instance\.py/ nocase ascii wide
                        $string25_Ninja_offensive_tool_keyword = "donut-shellcode" nocase ascii wide
                        $string26_Ninja_offensive_tool_keyword = /dropper_cs\.exe/ nocase ascii wide
                        $string27_Ninja_offensive_tool_keyword = /Find\-PSServiceAccounts\.ps1/ nocase ascii wide
                        $string28_Ninja_offensive_tool_keyword = /Follina\.Ninja/ nocase ascii wide
                        $string29_Ninja_offensive_tool_keyword = /Follina\/follina\.html/ nocase ascii wide
                        $string30_Ninja_offensive_tool_keyword = "Follina/Follinadoc" nocase ascii wide
                        $string31_Ninja_offensive_tool_keyword = /get_beacon\(/ nocase ascii wide
                        $string32_Ninja_offensive_tool_keyword = "Invoke-Kerberoast" nocase ascii wide
                        $string33_Ninja_offensive_tool_keyword = /Invoke\-Kerberoast\.ps1/ nocase ascii wide
                        $string34_Ninja_offensive_tool_keyword = "Invoke-Mimikatz-old" nocase ascii wide
                        $string35_Ninja_offensive_tool_keyword = "Invoke-WMIExec" nocase ascii wide
                        $string36_Ninja_offensive_tool_keyword = /Kerberoast\.py/ nocase ascii wide
                        $string37_Ninja_offensive_tool_keyword = "Ninja c2" nocase ascii wide
                        $string38_Ninja_offensive_tool_keyword = "ninjac2" nocase ascii wide
                        $string39_Ninja_offensive_tool_keyword = /Obfuscate\.py/ nocase ascii wide
                        $string40_Ninja_offensive_tool_keyword = "payloads/Follina" nocase ascii wide
                        $string41_Ninja_offensive_tool_keyword = "payloads/Powershell" nocase ascii wide
                        $string42_Ninja_offensive_tool_keyword = "payloads/shellcodes" nocase ascii wide
                        $string43_Ninja_offensive_tool_keyword = /python3\sNinja\.py/ nocase ascii wide
                        $string44_Ninja_offensive_tool_keyword = /python3\sstart_campaign\.py/ nocase ascii wide
                        $string45_Ninja_offensive_tool_keyword = /safetydump\.ninja/ nocase ascii wide
                        $string46_Ninja_offensive_tool_keyword = /safetydump\.ninja/ nocase ascii wide
                        $string47_Ninja_offensive_tool_keyword = /SharpHound\.ps1/ nocase ascii wide
                        $string48_Ninja_offensive_tool_keyword = /simple_dropper\.ninja/ nocase ascii wide
                        $string49_Ninja_offensive_tool_keyword = "webshell_execute" nocase ascii wide
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