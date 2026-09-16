rule mailpv
{
    meta:
        description = "Detection patterns for the tool 'mailpv' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mailpv"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /mailpv\.exe/ nocase ascii wide
                        $string2 = /mailpv\.zip/ nocase ascii wide

    condition:
        any of them
}