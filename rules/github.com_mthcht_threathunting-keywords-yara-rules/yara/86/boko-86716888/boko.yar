rule boko
{
    meta:
        description = "Detection patterns for the tool 'boko' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "boko"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/bashexplode/boko"
                        $string2 = /\/boko\.py/ nocase ascii wide
                        $string3 = "BackdoorableScript" nocase ascii wide
                        $string4 = /boko\.py\s/ nocase ascii wide
                        $string5 = /bokoscanner\./ nocase ascii wide
                        $string6 = "import boko" nocase ascii wide

    condition:
        any of them
}