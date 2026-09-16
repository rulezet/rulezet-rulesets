rule rule_AMSITrigger_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AMSITrigger' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AMSITrigger"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_AMSITrigger_offensive_tool_keyword = /\/AMSITrigger\.git/ nocase ascii wide
                        $string2_AMSITrigger_offensive_tool_keyword = /\\AmsiTrigger\.csproj/ nocase ascii wide
                        $string3_AMSITrigger_offensive_tool_keyword = /\\AmsiTrigger\.sln/ nocase ascii wide
                        $string4_AMSITrigger_offensive_tool_keyword = /\\AMSITrigger\\/ nocase ascii wide
                        $string5_AMSITrigger_offensive_tool_keyword = /\\AMSITrigger\-master/ nocase ascii wide
                        $string6_AMSITrigger_offensive_tool_keyword = "056a00cd961e5d38f464d6a15393c92f3f0cef668e396f9595822e7147b4c25e" nocase ascii wide
                        $string7_AMSITrigger_offensive_tool_keyword = "0aa6a04c0e8bb0022ccbe0c6f2bf6bc1806c59ffffae3981ae083e49e78573b7" nocase ascii wide
                        $string8_AMSITrigger_offensive_tool_keyword = "453c7fcdf6fdf446f846057eb2cd90b495caaf442aa07dbeb9655482809fef43" nocase ascii wide
                        $string9_AMSITrigger_offensive_tool_keyword = "66c00239681d0f5822544fa18f461864df248a0dc5a76c4a3f981dac5af89162" nocase ascii wide
                        $string10_AMSITrigger_offensive_tool_keyword = "7864978aad22ff10f75864376b0e57d7ec3ba8bd84e663c2c650f5fc45a9b388" nocase ascii wide
                        $string11_AMSITrigger_offensive_tool_keyword = "8BAAEFF6-1840-4430-AA05-47F2877E3235" nocase ascii wide
                        $string12_AMSITrigger_offensive_tool_keyword = "971f7d595c07fa302de6843e85ae22c771bc23a790f4092b5e6cd62fac985ab0" nocase ascii wide
                        $string13_AMSITrigger_offensive_tool_keyword = /AmsiTrigger\.exe/ nocase ascii wide
                        $string14_AMSITrigger_offensive_tool_keyword = /AmsiTrigger_x64\.exe/ nocase ascii wide
                        $string15_AMSITrigger_offensive_tool_keyword = /AmsiTrigger_x86\.exe/ nocase ascii wide
                        $string16_AMSITrigger_offensive_tool_keyword = "assembly AMSITrigger " nocase ascii wide
                        $string17_AMSITrigger_offensive_tool_keyword = "ca081dfda125f3b14589e205288777bdc209941e50cebb2298262adcd5c76c86" nocase ascii wide
                        $string18_AMSITrigger_offensive_tool_keyword = "f1bdbea3a5f869e83b52e6284e24d76049a3505492a8b7176cb07f2ad03cbe2b" nocase ascii wide
                        $string19_AMSITrigger_offensive_tool_keyword = "RythmStick/AMSITrigger" nocase ascii wide
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
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}