rule rule_adsearch_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'adsearch' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adsearch"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_adsearch_offensive_tool_keyword = /\s\-\-search\s\\"\(\&\(objectCategory\=computer\)\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=524288\)\)/ nocase ascii wide
                        $string2_adsearch_offensive_tool_keyword = /\s\-\-search\s\\"\(\&\(objectCategory\=group\)\(cn\=.{0,1000}Admins/ nocase ascii wide
                        $string3_adsearch_offensive_tool_keyword = /\s\-\-search\s\\"\(\&\(objectCategory\=group\)\(cn\=MS\sSQL\sAdmins\)/ nocase ascii wide
                        $string4_adsearch_offensive_tool_keyword = /\s\-\-search\s\\"\(\&\(objectCategory\=user\)\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=4194304\)\)/ nocase ascii wide
                        $string5_adsearch_offensive_tool_keyword = /\/ADSearch\.git/ nocase ascii wide
                        $string6_adsearch_offensive_tool_keyword = /adsearch.{0,1000}\s\-\-domain\-admins/ nocase ascii wide
                        $string7_adsearch_offensive_tool_keyword = /adsearch\.exe/ nocase ascii wide
                        $string8_adsearch_offensive_tool_keyword = /ADSearch\.sln/ nocase ascii wide
                        $string9_adsearch_offensive_tool_keyword = /ADSearch\\ADSearch\.cs/ nocase ascii wide
                        $string10_adsearch_offensive_tool_keyword = /adsearch\-master\.zip/ nocase ascii wide
                        $string11_adsearch_offensive_tool_keyword = "tomcarver16/ADSearch" nocase ascii wide

    condition:
        any of them
}