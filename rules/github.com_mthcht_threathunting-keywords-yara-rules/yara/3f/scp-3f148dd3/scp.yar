rule scp
{
    meta:
        description = "Detection patterns for the tool 'scp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "scp"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /scp\s.{0,1000}\s.{0,1000}\@.{0,1000}\:/ nocase ascii wide
                        $string2 = /scp\s.{0,1000}\@.{0,1000}\:.{0,1000}\s/ nocase ascii wide

    condition:
        any of them
}