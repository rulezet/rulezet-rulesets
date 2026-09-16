rule rule_ADAPE_Script_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ADAPE-Script' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ADAPE-Script"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ADAPE_Script_offensive_tool_keyword = " \"Sniffy boi sniffin\"" nocase ascii wide
                        $string2_ADAPE_Script_offensive_tool_keyword = /\sADAPE\.ps1/ nocase ascii wide
                        $string3_ADAPE_Script_offensive_tool_keyword = /\$Kerberoast/ nocase ascii wide
                        $string4_ADAPE_Script_offensive_tool_keyword = /\.ps1\s\-GPP\s\-PView\s\-Kerberoast/ nocase ascii wide
                        $string5_ADAPE_Script_offensive_tool_keyword = /\.ps1\s\-PrivEsc/ nocase ascii wide
                        $string6_ADAPE_Script_offensive_tool_keyword = /\/ADAPE\.ps1/ nocase ascii wide
                        $string7_ADAPE_Script_offensive_tool_keyword = /\/ADAPE\-Script\.git/ nocase ascii wide
                        $string8_ADAPE_Script_offensive_tool_keyword = /\/Inveigh\.ps1/ nocase ascii wide
                        $string9_ADAPE_Script_offensive_tool_keyword = /\/PowerUp\.ps1/ nocase ascii wide
                        $string10_ADAPE_Script_offensive_tool_keyword = /\/PowerView\.ps1/ nocase ascii wide
                        $string11_ADAPE_Script_offensive_tool_keyword = /\/PrivEsc\.psm1/ nocase ascii wide
                        $string12_ADAPE_Script_offensive_tool_keyword = /\/PView\.psm1/ nocase ascii wide
                        $string13_ADAPE_Script_offensive_tool_keyword = /\\ADAPE\.ps1/ nocase ascii wide
                        $string14_ADAPE_Script_offensive_tool_keyword = /\\ExploitableSystem\.txt/ nocase ascii wide
                        $string15_ADAPE_Script_offensive_tool_keyword = /\\PrivEsc\.txt/ nocase ascii wide
                        $string16_ADAPE_Script_offensive_tool_keyword = /\\ShareFinder\.txt/ nocase ascii wide
                        $string17_ADAPE_Script_offensive_tool_keyword = "7f99e59cb3242638aa4967180674b98dd770fae51a85ff364238faf52e02a586" nocase ascii wide
                        $string18_ADAPE_Script_offensive_tool_keyword = "Attemping WPAD, LLMNR, and NBTNS poisoning" nocase ascii wide
                        $string19_ADAPE_Script_offensive_tool_keyword = "Author: @haus3c" nocase ascii wide
                        $string20_ADAPE_Script_offensive_tool_keyword = "Collecting Privesc methods" nocase ascii wide
                        $string21_ADAPE_Script_offensive_tool_keyword = "function PrivEsc" nocase ascii wide
                        $string22_ADAPE_Script_offensive_tool_keyword = "Get-ExploitableSystem -Verbose" nocase ascii wide
                        $string23_ADAPE_Script_offensive_tool_keyword = /Get\-GPPPassword\.ps1/ nocase ascii wide
                        $string24_ADAPE_Script_offensive_tool_keyword = "hausec/ADAPE-Script" nocase ascii wide
                        $string25_ADAPE_Script_offensive_tool_keyword = /Import\-Module\s.{0,100}\/PView\.psm1/ nocase ascii wide
                        $string26_ADAPE_Script_offensive_tool_keyword = "Invoke-Kerberoast" nocase ascii wide
                        $string27_ADAPE_Script_offensive_tool_keyword = "Invoke-ShareFinder -CheckShareAccess" nocase ascii wide
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