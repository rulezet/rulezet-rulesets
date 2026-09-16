rule rule_spiderfoot_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'spiderfoot' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "spiderfoot"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_spiderfoot_offensive_tool_keyword = /\s\.\/sf\.py\s\-l\s127\.0\.0\.1\:5001/
                        $string2_spiderfoot_offensive_tool_keyword = /\/sfp_openphish\.py/
                        $string3_spiderfoot_offensive_tool_keyword = /\/sfp_spider\.py/
                        $string4_spiderfoot_offensive_tool_keyword = /\/SpiderFoot\-.{0,1000}\.log\.cs/
                        $string5_spiderfoot_offensive_tool_keyword = /\/SpiderFoot\.csv/
                        $string6_spiderfoot_offensive_tool_keyword = /\/spiderfoot\.git/ nocase ascii wide
                        $string7_spiderfoot_offensive_tool_keyword = /\/subdomains\-10000\.txt/
                        $string8_spiderfoot_offensive_tool_keyword = /dicts.{0,1000}generic\-usernames\.txt/ nocase ascii wide
                        $string9_spiderfoot_offensive_tool_keyword = /sfp_portscan_tcp\.py/ nocase ascii wide
                        $string10_spiderfoot_offensive_tool_keyword = /sfp_torexits\.py/ nocase ascii wide
                        $string11_spiderfoot_offensive_tool_keyword = "smicallef/spiderfoot" nocase ascii wide
                        $string12_spiderfoot_offensive_tool_keyword = /\-SpiderFoot\-correlations\.csv/ nocase ascii wide
                        $string13_spiderfoot_offensive_tool_keyword = "spiderfoot-master" nocase ascii wide

    condition:
        any of them
}