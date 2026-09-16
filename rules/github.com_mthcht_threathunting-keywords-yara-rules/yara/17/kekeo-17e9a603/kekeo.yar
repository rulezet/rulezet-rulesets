rule kekeo
{
    meta:
        description = "Detection patterns for the tool 'kekeo' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "kekeo"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /kirbikator\.exe/ nocase ascii wide

    condition:
        any of them
}