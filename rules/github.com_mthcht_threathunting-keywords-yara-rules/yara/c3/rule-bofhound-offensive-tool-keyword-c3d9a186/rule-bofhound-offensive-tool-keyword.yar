rule rule_bofhound_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'bofhound' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bofhound"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_bofhound_offensive_tool_keyword = " Brc4LdapSentinelParser" nocase ascii wide
                        $string2_bofhound_offensive_tool_keyword = " --brute-ratel" nocase ascii wide
                        $string3_bofhound_offensive_tool_keyword = /\/beacon_202_no_acl\.log/
                        $string4_bofhound_offensive_tool_keyword = /\/beacon_257\-objects\.log/
                        $string5_bofhound_offensive_tool_keyword = /\/bloodhound_domain\.py/ nocase ascii wide
                        $string6_bofhound_offensive_tool_keyword = /\/bloodhound_domaintrust\.py/ nocase ascii wide
                        $string7_bofhound_offensive_tool_keyword = /\/bloodhound_gpo\.py/ nocase ascii wide
                        $string8_bofhound_offensive_tool_keyword = /\/bloodhound_object\.py/ nocase ascii wide
                        $string9_bofhound_offensive_tool_keyword = /\/bloodhound_ou\.py/ nocase ascii wide
                        $string10_bofhound_offensive_tool_keyword = /\/bloodhound_schema\.py/ nocase ascii wide
                        $string11_bofhound_offensive_tool_keyword = /\/bofhound\.git/ nocase ascii wide
                        $string12_bofhound_offensive_tool_keyword = /\/ldap_search_bof\.py/ nocase ascii wide
                        $string13_bofhound_offensive_tool_keyword = "/opt/cobaltstrike/logs"
                        $string14_bofhound_offensive_tool_keyword = /\\ldap_search_bof\.py/ nocase ascii wide
                        $string15_bofhound_offensive_tool_keyword = /badger_no_acl_1030_objects\.log/ nocase ascii wide
                        $string16_bofhound_offensive_tool_keyword = "bofhound --" nocase ascii wide
                        $string17_bofhound_offensive_tool_keyword = "bofhound -i " nocase ascii wide
                        $string18_bofhound_offensive_tool_keyword = "bofhound -o " nocase ascii wide
                        $string19_bofhound_offensive_tool_keyword = "bofhound-main" nocase ascii wide
                        $string20_bofhound_offensive_tool_keyword = /brc4_ldap_sentinel\.py/ nocase ascii wide
                        $string21_bofhound_offensive_tool_keyword = "fortalice/bofhound" nocase ascii wide
                        $string22_bofhound_offensive_tool_keyword = "from bofhound import " nocase ascii wide
                        $string23_bofhound_offensive_tool_keyword = /from\sbofhound\.ad\simport/ nocase ascii wide
                        $string24_bofhound_offensive_tool_keyword = "import LdapSearchBofParser" nocase ascii wide
                        $string25_bofhound_offensive_tool_keyword = "pip3 install bofhound" nocase ascii wide
                        $string26_bofhound_offensive_tool_keyword = "poetry run bofhound" nocase ascii wide
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