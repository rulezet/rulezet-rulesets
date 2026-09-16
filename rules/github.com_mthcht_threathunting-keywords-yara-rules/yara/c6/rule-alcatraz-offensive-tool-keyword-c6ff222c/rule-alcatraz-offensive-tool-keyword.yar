rule rule_Alcatraz_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Alcatraz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Alcatraz"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Alcatraz_offensive_tool_keyword = /\sAlcatraz\.exe/ nocase ascii wide
                        $string2_Alcatraz_offensive_tool_keyword = /\/Alcatraz\.exe/ nocase ascii wide
                        $string3_Alcatraz_offensive_tool_keyword = /\/Alcatraz\.git/ nocase ascii wide
                        $string4_Alcatraz_offensive_tool_keyword = /\/Alcatraz\/files\/.{0,100}\/Alcatraz\.zip/ nocase ascii wide
                        $string5_Alcatraz_offensive_tool_keyword = "/Alcatraz/x64" nocase ascii wide
                        $string6_Alcatraz_offensive_tool_keyword = "/Alcatraz-gui" nocase ascii wide
                        $string7_Alcatraz_offensive_tool_keyword = /\/obfuscator\/obfuscator\./ nocase ascii wide
                        $string8_Alcatraz_offensive_tool_keyword = /\\Alcatraz\.exe/ nocase ascii wide
                        $string9_Alcatraz_offensive_tool_keyword = /Alcatraz\.sln/ nocase ascii wide
                        $string10_Alcatraz_offensive_tool_keyword = /Alcatraz\.vcxproj/ nocase ascii wide
                        $string11_Alcatraz_offensive_tool_keyword = "Alcatraz/obfuscator" nocase ascii wide
                        $string12_Alcatraz_offensive_tool_keyword = /Alcatraz\-master\.zip/ nocase ascii wide
                        $string13_Alcatraz_offensive_tool_keyword = /obfuscator.{0,100}antidisassembly\./ nocase ascii wide
                        $string14_Alcatraz_offensive_tool_keyword = /obfuscator\.cpp/ nocase ascii wide
                        $string15_Alcatraz_offensive_tool_keyword = "weak1337/Alcatraz" nocase ascii wide
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