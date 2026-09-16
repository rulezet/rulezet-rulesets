rule p0f
{
    meta:
        description = "Detection patterns for the tool 'p0f' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "p0f"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/tmp\/p0f\.log/
                        $string2 = "install p0f" nocase ascii wide
                        $string3 = /p0f\s\-i\seth.{0,1000}\s\-p/ nocase ascii wide
                        $string4 = /p0f\/p0f\.fp/ nocase ascii wide

    condition:
        any of them
}