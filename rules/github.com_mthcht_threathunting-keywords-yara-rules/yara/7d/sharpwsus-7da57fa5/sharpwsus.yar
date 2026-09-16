rule SharpWSUS
{
    meta:
        description = "Detection patterns for the tool 'SharpWSUS' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpWSUS"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.exe\screate\s\/payload.{0,1000}\s\/kb/ nocase ascii wide
                        $string2 = "/SharpWSUS" nocase ascii wide
                        $string3 = "sharpwsus locate" nocase ascii wide
                        $string4 = "SharpWSUS" nocase ascii wide
                        $string5 = /SharpWSUS\./ nocase ascii wide

    condition:
        any of them
}