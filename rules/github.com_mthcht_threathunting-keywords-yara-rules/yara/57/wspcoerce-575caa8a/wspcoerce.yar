rule WSPCoerce
{
    meta:
        description = "Detection patterns for the tool 'WSPCoerce' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WSPCoerce"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sWSPCoerce\.cs/ nocase ascii wide
                        $string2 = /\/WSPCoerce\.git/
                        $string3 = /\\WSPCoerce\.cs/ nocase ascii wide
                        $string4 = "slemire/WSPCoerce" nocase ascii wide
                        $string5 = /WSPCoerce\.ex/ nocase ascii wide
                        $string6 = "WSPCoerce-main" nocase ascii wide

    condition:
        any of them
}