rule rule_SharpHide_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpHide' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpHide"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpHide_offensive_tool_keyword = /\/SharpHide\.git/ nocase ascii wide
                        $string2_SharpHide_offensive_tool_keyword = /\/SharpHide\.git/ nocase ascii wide
                        $string3_SharpHide_offensive_tool_keyword = /\[\+\]\sSharpHide\srunning\sas\selevated\suser/ nocase ascii wide
                        $string4_SharpHide_offensive_tool_keyword = /\[\+\]\sSharpHide\srunning\sas\snormal\suser/ nocase ascii wide
                        $string5_SharpHide_offensive_tool_keyword = /\\Windows\\Temp\\Bla\.exe/ nocase ascii wide
                        $string6_SharpHide_offensive_tool_keyword = "443D8CBF-899C-4C22-B4F6-B7AC202D4E37" nocase ascii wide
                        $string7_SharpHide_offensive_tool_keyword = "66504e8c044a01ed3ef2a97dd36de68b7b1913d737d6ad4e6bd7778d80dec92f" nocase ascii wide
                        $string8_SharpHide_offensive_tool_keyword = "6ff0ec2a775575ab2724c254aa386c44155453c1ae020446a6fb5b0535de65d3" nocase ascii wide
                        $string9_SharpHide_offensive_tool_keyword = "outflanknl/SharpHide" nocase ascii wide
                        $string10_SharpHide_offensive_tool_keyword = "SharpHide running as elevated user" nocase ascii wide
                        $string11_SharpHide_offensive_tool_keyword = /SharpHide\.csproj/ nocase ascii wide
                        $string12_SharpHide_offensive_tool_keyword = /SharpHide\.exe/ nocase ascii wide
                        $string13_SharpHide_offensive_tool_keyword = /SharpHide\.sln/ nocase ascii wide
                        $string14_SharpHide_offensive_tool_keyword = "SharpHide-master" nocase ascii wide
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