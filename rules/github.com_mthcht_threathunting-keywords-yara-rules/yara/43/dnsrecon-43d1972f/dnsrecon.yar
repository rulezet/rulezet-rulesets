rule dnsrecon
{
    meta:
        description = "Detection patterns for the tool 'dnsrecon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dnsrecon"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-d\s.{0,1000}\s\-t\szonewalk/
                        $string2 = "dnsrecon"

    condition:
        any of them
}