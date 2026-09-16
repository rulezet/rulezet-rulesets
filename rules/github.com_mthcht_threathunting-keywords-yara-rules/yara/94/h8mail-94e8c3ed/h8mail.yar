rule h8mail
{
    meta:
        description = "Detection patterns for the tool 'h8mail' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "h8mail"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/h8mail/" nocase ascii wide
                        $string2 = "h8mail -" nocase ascii wide
                        $string3 = "h8mail" nocase ascii wide
                        $string4 = "install h8mail" nocase ascii wide
                        $string5 = "khast3x/h8mail" nocase ascii wide
                        $string6 = "opencubicles/h8mail" nocase ascii wide

    condition:
        any of them
}