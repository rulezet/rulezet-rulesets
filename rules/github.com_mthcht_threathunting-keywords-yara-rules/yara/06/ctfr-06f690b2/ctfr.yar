rule ctfr
{
    meta:
        description = "Detection patterns for the tool 'ctfr' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ctfr"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sctfr\.py/ nocase ascii wide
                        $string2 = /\/ctfr\.py/ nocase ascii wide
                        $string3 = /\\ctfr\.py/ nocase ascii wide

    condition:
        any of them
}