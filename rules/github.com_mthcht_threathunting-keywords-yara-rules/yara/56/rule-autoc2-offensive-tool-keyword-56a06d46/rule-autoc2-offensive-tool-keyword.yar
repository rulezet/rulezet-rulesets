rule rule_AutoC2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AutoC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AutoC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_AutoC2_offensive_tool_keyword = /\sCred_Dump\.sh/ nocase ascii wide
                        $string2_AutoC2_offensive_tool_keyword = /\sDefense_Evasion\.sh/ nocase ascii wide
                        $string3_AutoC2_offensive_tool_keyword = /\sExfil\.sh/ nocase ascii wide
                        $string4_AutoC2_offensive_tool_keyword = /\sHak5\.sh/ nocase ascii wide
                        $string5_AutoC2_offensive_tool_keyword = /\sPersistence\.sh/ nocase ascii wide
                        $string6_AutoC2_offensive_tool_keyword = /\sPriv_Esc\.sh/ nocase ascii wide
                        $string7_AutoC2_offensive_tool_keyword = /\.\/Exfil\.sh/
                        $string8_AutoC2_offensive_tool_keyword = /\.\/Phishing\.sh/
                        $string9_AutoC2_offensive_tool_keyword = /\/Cred_Dump\.sh/ nocase ascii wide
                        $string10_AutoC2_offensive_tool_keyword = /\/Defense_Evasion\.sh/
                        $string11_AutoC2_offensive_tool_keyword = /\/Hak5\.sh/
                        $string12_AutoC2_offensive_tool_keyword = "/opt/Password_Cracking/"
                        $string13_AutoC2_offensive_tool_keyword = /\/Persistence\.sh/
                        $string14_AutoC2_offensive_tool_keyword = /\/Phishing\.sh/
                        $string15_AutoC2_offensive_tool_keyword = /\/Priv_Esc\.sh/ nocase ascii wide
                        $string16_AutoC2_offensive_tool_keyword = /AutoC2\.sh/ nocase ascii wide
                        $string17_AutoC2_offensive_tool_keyword = /AutoC2\/All\.sh/ nocase ascii wide
                        $string18_AutoC2_offensive_tool_keyword = "AutoC2/C2" nocase ascii wide
                        $string19_AutoC2_offensive_tool_keyword = "AutoC2/Dependencies" nocase ascii wide
                        $string20_AutoC2_offensive_tool_keyword = "AutoC2/Initial_Access" nocase ascii wide
                        $string21_AutoC2_offensive_tool_keyword = /AutoC2\/Lateral\.sh/ nocase ascii wide
                        $string22_AutoC2_offensive_tool_keyword = "AutoC2/Payload_Development" nocase ascii wide
                        $string23_AutoC2_offensive_tool_keyword = "AutoC2/Recon" nocase ascii wide
                        $string24_AutoC2_offensive_tool_keyword = "AutoC2/Situational_Awareness" nocase ascii wide
                        $string25_AutoC2_offensive_tool_keyword = /AutoC2\/Social\.sh/ nocase ascii wide
                        $string26_AutoC2_offensive_tool_keyword = "AutoC2/Staging" nocase ascii wide
                        $string27_AutoC2_offensive_tool_keyword = /AutoC2\/Web\.sh/ nocase ascii wide
                        $string28_AutoC2_offensive_tool_keyword = /AutoC2\/Wireless\.sh/ nocase ascii wide
                        $string29_AutoC2_offensive_tool_keyword = "AutoC2/Wordlists" nocase ascii wide
                        $string30_AutoC2_offensive_tool_keyword = /Password_Cracking\.sh/ nocase ascii wide
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