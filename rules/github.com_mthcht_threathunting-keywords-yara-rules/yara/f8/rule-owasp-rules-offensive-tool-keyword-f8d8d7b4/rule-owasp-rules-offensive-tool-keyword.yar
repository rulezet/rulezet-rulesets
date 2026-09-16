rule rule_OWASP_rules_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'OWASP rules' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "OWASP rules"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_OWASP_rules_offensive_tool_keyword = "\"small web shell by zaco" nocase ascii wide
                        $string2_OWASP_rules_offensive_tool_keyword = /\/tmp\/evil\.sh/
                        $string3_OWASP_rules_offensive_tool_keyword = /\-\:\[GreenwooD\]\:\-\sWinX\sShell/ nocase ascii wide
                        $string4_OWASP_rules_offensive_tool_keyword = /\<h1\>\.\:NCC\:\.\sShell\sv/ nocase ascii wide
                        $string5_OWASP_rules_offensive_tool_keyword = /\<H1\>\<center\>\-\=\[\+\]\sIDBTEAM\sSHELLS/ nocase ascii wide
                        $string6_OWASP_rules_offensive_tool_keyword = "<h2>Laudanum Tools" nocase ascii wide
                        $string7_OWASP_rules_offensive_tool_keyword = /\<head\>\<title\>Wardom\s\|\sNe\sMutlu\sT/ nocase ascii wide
                        $string8_OWASP_rules_offensive_tool_keyword = "<title>Sosyete Safe Mode Bypass Shell -" nocase ascii wide
                        $string9_OWASP_rules_offensive_tool_keyword = "<title>SyRiAn Sh3ll ~" nocase ascii wide
                        $string10_OWASP_rules_offensive_tool_keyword = "<title>WebRoot Hack Tools\"" nocase ascii wide
                        $string11_OWASP_rules_offensive_tool_keyword = /\=\[\s1n73ct10n\sprivat\sshell\s\]\=/ nocase ascii wide
                        $string12_OWASP_rules_offensive_tool_keyword = /\-\-\=\=\[\[\sAndela\sYuwono\sPriv8\sShell\s\]\]\=\=\-\-/ nocase ascii wide
                        $string13_OWASP_rules_offensive_tool_keyword = "0byt3m1n1-V2" nocase ascii wide
                        $string14_OWASP_rules_offensive_tool_keyword = "BloodSecurity Hackers Shell" nocase ascii wide
                        $string15_OWASP_rules_offensive_tool_keyword = /chmod\s\+x\sevil\.php/
                        $string16_OWASP_rules_offensive_tool_keyword = /Con7ext\sShell\sV\.2/ nocase ascii wide
                        $string17_OWASP_rules_offensive_tool_keyword = "CUPLIS BYPASSS SHELL" nocase ascii wide
                        $string18_OWASP_rules_offensive_tool_keyword = "Dive Shell - Emperor Hacking Team" nocase ascii wide
                        $string19_OWASP_rules_offensive_tool_keyword = "G-Security Webshell" nocase ascii wide
                        $string20_OWASP_rules_offensive_tool_keyword = /h4ntu\sshell\s\[powered\sby\stsoi\]/ nocase ascii wide
                        $string21_OWASP_rules_offensive_tool_keyword = "Laudanum PHP File Browser" nocase ascii wide
                        $string22_OWASP_rules_offensive_tool_keyword = "Laudanum PHP Hostname by IP Lookup" nocase ascii wide
                        $string23_OWASP_rules_offensive_tool_keyword = "Laudanum PHP Proxy" nocase ascii wide
                        $string24_OWASP_rules_offensive_tool_keyword = "Laudanum PHP Shell Access" nocase ascii wide
                        $string25_OWASP_rules_offensive_tool_keyword = "Loader'z WEB shell" nocase ascii wide
                        $string26_OWASP_rules_offensive_tool_keyword = /Lolipop\.php\s\-\sEdited\sBy\sKingDefacer/ nocase ascii wide
                        $string27_OWASP_rules_offensive_tool_keyword = "Simple PHP backdoor by DK" nocase ascii wide
                        $string28_OWASP_rules_offensive_tool_keyword = "SimShell - Simorgh Security MGZ" nocase ascii wide
                        $string29_OWASP_rules_offensive_tool_keyword = "Small Shell - Edited By KingDefacer" nocase ascii wide
                        $string30_OWASP_rules_offensive_tool_keyword = /Yourman\.sh\sMini\sShell/
                        $string31_OWASP_rules_offensive_tool_keyword = /ZEROSHELL\s\|\sZEROSTORE/ nocase ascii wide
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