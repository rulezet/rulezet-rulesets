rule trevorc2
{
    meta:
        description = "Detection patterns for the tool 'trevorc2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "trevorc2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "pSNIRFgTuZnCdHN" nocase ascii wide
                        $string2 = "TrevorC2" nocase ascii wide

    condition:
        any of them
}