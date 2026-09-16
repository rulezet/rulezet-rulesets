rule dsniff
{
    meta:
        description = "Detection patterns for the tool 'dsniff' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dsniff"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/dnsspoof\.c/
                        $string2 = /\/dsniff\.c/
                        $string3 = /\/dsniff\.services/
                        $string4 = "tecknicaltom/dsniff" nocase ascii wide

    condition:
        any of them
}