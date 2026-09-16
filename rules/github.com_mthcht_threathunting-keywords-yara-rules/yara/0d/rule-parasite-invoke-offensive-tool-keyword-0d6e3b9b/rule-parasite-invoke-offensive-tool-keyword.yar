rule rule_Parasite_Invoke_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Parasite-Invoke' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Parasite-Invoke"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Parasite_Invoke_offensive_tool_keyword = /\sParasite\sInvoke\.exe/ nocase ascii wide
                        $string2_Parasite_Invoke_offensive_tool_keyword = /\.\sNice\sassembly\s\:D\s\./ nocase ascii wide
                        $string3_Parasite_Invoke_offensive_tool_keyword = /\.exe\s\-\-path\sC\:\\\s\-r\s\-\-method\sVirtualAlloc/ nocase ascii wide
                        $string4_Parasite_Invoke_offensive_tool_keyword = /\/Parasite\sInvoke\.exe/ nocase ascii wide
                        $string5_Parasite_Invoke_offensive_tool_keyword = /\/Parasite\%20Invoke\.exe/ nocase ascii wide
                        $string6_Parasite_Invoke_offensive_tool_keyword = /\/Parasite\-Invoke\.git/ nocase ascii wide
                        $string7_Parasite_Invoke_offensive_tool_keyword = /\\Parasite\sInvoke\.csproj/ nocase ascii wide
                        $string8_Parasite_Invoke_offensive_tool_keyword = /\\Parasite\sInvoke\.exe/ nocase ascii wide
                        $string9_Parasite_Invoke_offensive_tool_keyword = /\\Parasite\sInvoke\.pdb/ nocase ascii wide
                        $string10_Parasite_Invoke_offensive_tool_keyword = /\\Parasite\sInvoke\.sln/ nocase ascii wide
                        $string11_Parasite_Invoke_offensive_tool_keyword = /\\Parasite\sInvoke\\/ nocase ascii wide
                        $string12_Parasite_Invoke_offensive_tool_keyword = /\\Parasite\-Invoke\-main/ nocase ascii wide
                        $string13_Parasite_Invoke_offensive_tool_keyword = "===PARASITE INVOKE" nocase ascii wide
                        $string14_Parasite_Invoke_offensive_tool_keyword = "7CEC7793-3E22-455B-9E88-94B8D1A8F78D" nocase ascii wide
                        $string15_Parasite_Invoke_offensive_tool_keyword = /https\:\/\/pastebin\.com\/9JyjcMAH/ nocase ascii wide
                        $string16_Parasite_Invoke_offensive_tool_keyword = /https\:\/\/pastebin\.com\/iBeTbXCw/ nocase ascii wide
                        $string17_Parasite_Invoke_offensive_tool_keyword = /Michael\sZhmaylo\s\(github\.com\// nocase ascii wide
                        $string18_Parasite_Invoke_offensive_tool_keyword = "MzHmO/Parasite-Invoke" nocase ascii wide
                        $string19_Parasite_Invoke_offensive_tool_keyword = /Parasite\sInvoke_\.\-\'/ nocase ascii wide
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