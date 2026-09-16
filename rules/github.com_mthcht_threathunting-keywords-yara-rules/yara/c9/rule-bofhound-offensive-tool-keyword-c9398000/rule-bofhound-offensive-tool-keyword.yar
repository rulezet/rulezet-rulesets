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

    condition:
        any of them
}