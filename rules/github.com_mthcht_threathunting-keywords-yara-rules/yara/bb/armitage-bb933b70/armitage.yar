rule armitage
{
    meta:
        description = "Detection patterns for the tool 'armitage' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "armitage"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " install armitage" nocase ascii wide
                        $string2 = /\.\/teamserver\s/
                        $string3 = /\/armitage\.git/ nocase ascii wide
                        $string4 = /\/passhash\.sl/ nocase ascii wide
                        $string5 = /armitage\.exe/ nocase ascii wide
                        $string6 = /meterpreter\.sl/ nocase ascii wide

    condition:
        any of them
}