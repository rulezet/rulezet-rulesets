rule spiderfoot
{
    meta:
        description = "Detection patterns for the tool 'spiderfoot' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "spiderfoot"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\.\/sf\.py\s\-l\s127\.0\.0\.1\:5001/
                        $string2 = /\/sfp_openphish\.py/
                        $string3 = /\/sfp_spider\.py/
                        $string4 = /\/SpiderFoot\-.{0,1000}\.log\.cs/
                        $string5 = /\/SpiderFoot\.csv/
                        $string6 = /\/spiderfoot\.git/ nocase ascii wide
                        $string7 = /\/subdomains\-10000\.txt/
                        $string8 = /dicts.{0,1000}generic\-usernames\.txt/ nocase ascii wide
                        $string9 = /sfp_portscan_tcp\.py/ nocase ascii wide
                        $string10 = /sfp_torexits\.py/ nocase ascii wide
                        $string11 = "smicallef/spiderfoot" nocase ascii wide
                        $string12 = /\-SpiderFoot\-correlations\.csv/ nocase ascii wide
                        $string13 = "spiderfoot-master" nocase ascii wide

    condition:
        any of them
}