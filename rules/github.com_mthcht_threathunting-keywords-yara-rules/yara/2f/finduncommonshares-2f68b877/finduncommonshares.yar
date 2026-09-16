rule FindUncommonShares
{
    meta:
        description = "Detection patterns for the tool 'FindUncommonShares' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FindUncommonShares"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\-\-dc\-ip\s.{0,1000}\-\-check\-user\-access/ nocase ascii wide
                        $string2 = /FindUncommonShares\.git/ nocase ascii wide
                        $string3 = /FindUncommonShares\.py\s/ nocase ascii wide
                        $string4 = "FindUncommonShares-main" nocase ascii wide

    condition:
        any of them
}