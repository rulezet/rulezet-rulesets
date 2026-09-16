rule rule_ldapsearch_ad_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ldapsearch-ad' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ldapsearch-ad"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ldapsearch_ad_offensive_tool_keyword = /\s\-\-server\s.{0,1000}\s\-\-type\spass\-pols/
                        $string2_ldapsearch_ad_offensive_tool_keyword = " --type asreproast"
                        $string3_ldapsearch_ad_offensive_tool_keyword = " --type search-spn"
                        $string4_ldapsearch_ad_offensive_tool_keyword = /\/ldapsearch\-ad\.git/
                        $string5_ldapsearch_ad_offensive_tool_keyword = /ldapsearchad\.py/
                        $string6_ldapsearch_ad_offensive_tool_keyword = /ldapsearch\-ad\.py/

    condition:
        any of them
}