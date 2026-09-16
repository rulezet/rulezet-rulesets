rule ifconfig
{
    meta:
        description = "Detection patterns for the tool 'ifconfig' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ifconfig"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /ifconfig\s.{0,1000}\shw\sether\s/ nocase ascii wide
                        $string2 = /ifconfig\s.{0,1000}\shw\sether\s.{0,1000}\:.{0,1000}\:/ nocase ascii wide

    condition:
        any of them
}