rule rule_NetshRun_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'NetshRun' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NetshRun"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_NetshRun_greyware_tool_keyword = /\/netshrun\.c/ nocase ascii wide
                        $string2_NetshRun_greyware_tool_keyword = /netsh\.exe\sadd\shelper\s.{0,1000}\\temp\\.{0,1000}\.dll/ nocase ascii wide
                        $string3_NetshRun_greyware_tool_keyword = /netshrun\.dll/ nocase ascii wide
                        $string4_NetshRun_greyware_tool_keyword = /PSBits.{0,1000}NetShRun/ nocase ascii wide

    condition:
        any of them
}