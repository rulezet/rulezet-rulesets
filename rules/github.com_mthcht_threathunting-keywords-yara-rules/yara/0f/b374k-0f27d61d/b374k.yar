rule b374k
{
    meta:
        description = "Detection patterns for the tool 'b374k' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "b374k"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/B374K" nocase ascii wide
                        $string2 = /B374K.{0,1000}index\.php/ nocase ascii wide
                        $string3 = /php\s\-f\s.{0,1000}\.php\s\-\-\s\-o\smyShell\.php/ nocase ascii wide

    condition:
        any of them
}