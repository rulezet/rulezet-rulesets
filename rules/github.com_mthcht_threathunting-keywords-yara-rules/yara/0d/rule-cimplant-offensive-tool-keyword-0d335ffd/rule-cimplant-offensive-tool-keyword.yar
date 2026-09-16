rule rule_CIMplant_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'CIMplant' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CIMplant"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_CIMplant_offensive_tool_keyword = " -c active_users -u " nocase ascii wide
                        $string2_CIMplant_offensive_tool_keyword = " -c command_exec --execute tasklist" nocase ascii wide
                        $string3_CIMplant_offensive_tool_keyword = " -c command_exec --execute whoami" nocase ascii wide
                        $string4_CIMplant_offensive_tool_keyword = " -c edr_query " nocase ascii wide
                        $string5_CIMplant_offensive_tool_keyword = /\s\-c\slogon_events\s.{0,100}\s\-u\s/ nocase ascii wide
                        $string6_CIMplant_offensive_tool_keyword = /\s\-c\sls\s\-\-directory\s.{0,100}\s\-u\s.{0,100}\s\-p\s/ nocase ascii wide
                        $string7_CIMplant_offensive_tool_keyword = " -c process_kill --process " nocase ascii wide
                        $string8_CIMplant_offensive_tool_keyword = " -c service_mod --execute create -s " nocase ascii wide
                        $string9_CIMplant_offensive_tool_keyword = /\s\-c\supload\s\-\-fileto\s.{0,100}\s\-\-file\s/ nocase ascii wide
                        $string10_CIMplant_offensive_tool_keyword = /\s\-c\svacant_system\s.{0,100}\s\-u\s/ nocase ascii wide
                        $string11_CIMplant_offensive_tool_keyword = /\sCIMplant\.exe/ nocase ascii wide
                        $string12_CIMplant_offensive_tool_keyword = /\s\-s\s.{0,100}\s\-c\scommand_exec\s\-\-execute\s/ nocase ascii wide
                        $string13_CIMplant_offensive_tool_keyword = /\s\-s\s.{0,100}\s\-c\sdisable_wdigest\s/ nocase ascii wide
                        $string14_CIMplant_offensive_tool_keyword = /\s\-s\s.{0,100}\s\-c\sdisable_winrm\s/ nocase ascii wide
                        $string15_CIMplant_offensive_tool_keyword = /\s\-s\s.{0,100}\s\-c\senable_wdigest\s/ nocase ascii wide
                        $string16_CIMplant_offensive_tool_keyword = /\s\-s\s.{0,100}\s\-c\senable_winrm\s/ nocase ascii wide
                        $string17_CIMplant_offensive_tool_keyword = /\s\-s\s.{0,100}\s\-c\sremote_posh\s/ nocase ascii wide
                        $string18_CIMplant_offensive_tool_keyword = " --service fortynorth" nocase ascii wide
                        $string19_CIMplant_offensive_tool_keyword = /\.exe\s\-s\s.{0,100}\s\-c\sservice_mod\s/ nocase ascii wide
                        $string20_CIMplant_offensive_tool_keyword = /\/CIMplant\.exe/ nocase ascii wide
                        $string21_CIMplant_offensive_tool_keyword = /\/CIMplant\.git/ nocase ascii wide
                        $string22_CIMplant_offensive_tool_keyword = /\/CIMplant\/Commander\.cs/ nocase ascii wide
                        $string23_CIMplant_offensive_tool_keyword = /\\CIMplant\.exe/ nocase ascii wide
                        $string24_CIMplant_offensive_tool_keyword = /CIMplant\.exe\s/ nocase ascii wide
                        $string25_CIMplant_offensive_tool_keyword = /CIMplant\.sln/ nocase ascii wide
                        $string26_CIMplant_offensive_tool_keyword = "CIMplant-main" nocase ascii wide
                        $string27_CIMplant_offensive_tool_keyword = "FortyNorthSecurity/CIMplant" nocase ascii wide
                        $string28_CIMplant_offensive_tool_keyword = "RedSiege/CIMplant" nocase ascii wide
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