rule rule_smartbrute_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'smartbrute' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "smartbrute"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_smartbrute_offensive_tool_keyword = " --bf-hashes-file " nocase ascii wide
                        $string2_smartbrute_offensive_tool_keyword = " --bf-passwords-file " nocase ascii wide
                        $string3_smartbrute_offensive_tool_keyword = " --ccache-ticket " nocase ascii wide
                        $string4_smartbrute_offensive_tool_keyword = " --neo4j-host " nocase ascii wide
                        $string5_smartbrute_offensive_tool_keyword = " -neo4j-password " nocase ascii wide
                        $string6_smartbrute_offensive_tool_keyword = " --neo4j-port " nocase ascii wide
                        $string7_smartbrute_offensive_tool_keyword = " --neo4j-user " nocase ascii wide
                        $string8_smartbrute_offensive_tool_keyword = /\/smartbrute\.git/ nocase ascii wide
                        $string9_smartbrute_offensive_tool_keyword = "/smartbrute-main"
                        $string10_smartbrute_offensive_tool_keyword = /\[bruteforce_mode\]/ nocase ascii wide
                        $string11_smartbrute_offensive_tool_keyword = /\\smartbrute\\/ nocase ascii wide
                        $string12_smartbrute_offensive_tool_keyword = /\\smartbrute\-main/ nocase ascii wide
                        $string13_smartbrute_offensive_tool_keyword = "52b07bced660711b3aa82b4cbf40156689045bcd695df40b1376c76e172beb8d" nocase ascii wide
                        $string14_smartbrute_offensive_tool_keyword = /Bad\spassword\scounts\sdont\sreplicate\sbetween\sdomain\scontrollers\.\sOnly\sthe\sPDC\sknows\sthe\sreal\samount\sof\sthose\.\sBe\ssure\sto\starget\sthe\sPDC\sso\sthat\saccounts\sdon\'t\sget\slocked\sout/ nocase ascii wide
                        $string15_smartbrute_offensive_tool_keyword = /bruteforce_attack\(/ nocase ascii wide
                        $string16_smartbrute_offensive_tool_keyword = "bruteforce_mode_kerberos_mode" nocase ascii wide
                        $string17_smartbrute_offensive_tool_keyword = "bruteforce_mode_ntlm_mode" nocase ascii wide
                        $string18_smartbrute_offensive_tool_keyword = /bruteforce_try_password_or_hash\(/ nocase ascii wide
                        $string19_smartbrute_offensive_tool_keyword = /bruteforce_try_user\(/ nocase ascii wide
                        $string20_smartbrute_offensive_tool_keyword = /docstring\sfor\sbruteforce\./ nocase ascii wide
                        $string21_smartbrute_offensive_tool_keyword = "Fetching domain information through a Kerberos auth over LDAP" nocase ascii wide
                        $string22_smartbrute_offensive_tool_keyword = "Fetching domain information through NTLM over LDAP" nocase ascii wide
                        $string23_smartbrute_offensive_tool_keyword = /options\.bruteforced_protocol/ nocase ascii wide
                        $string24_smartbrute_offensive_tool_keyword = "ShutdownRepo/smartbrute" nocase ascii wide
                        $string25_smartbrute_offensive_tool_keyword = /smart_try_password_or_hash\(/ nocase ascii wide
                        $string26_smartbrute_offensive_tool_keyword = "smartbrute%2520brute" nocase ascii wide
                        $string27_smartbrute_offensive_tool_keyword = /smartbrute\.py/ nocase ascii wide
                        $string28_smartbrute_offensive_tool_keyword = /smbrelayclient\.py/ nocase ascii wide
                        $string29_smartbrute_offensive_tool_keyword = "Starting bruteforce attack on " nocase ascii wide
                        $string30_smartbrute_offensive_tool_keyword = "The smart password spraying and bruteforcing tool for Active Directory Domain Services" nocase ascii wide
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