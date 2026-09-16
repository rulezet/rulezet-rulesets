rule NetshRun
{
    meta:
        description = "Detection patterns for the tool 'NetshRun' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NetshRun"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/netshrun\.c/ nocase ascii wide
                        $string2 = /netsh\.exe\sadd\shelper\s.{0,1000}\\temp\\.{0,1000}\.dll/ nocase ascii wide
                        $string3 = /netshrun\.dll/ nocase ascii wide
                        $string4 = /PSBits.{0,1000}NetShRun/ nocase ascii wide

    condition:
        any of them
}