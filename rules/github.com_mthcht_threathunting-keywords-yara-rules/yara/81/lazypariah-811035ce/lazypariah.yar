rule LAZYPARIAH
{
    meta:
        description = "Detection patterns for the tool 'LAZYPARIAH' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LAZYPARIAH"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " lazypariah" nocase ascii wide
                        $string2 = "lazypariah " nocase ascii wide
                        $string3 = /lazypariah\.svg/ nocase ascii wide
                        $string4 = "octetsplicer/LAZYPARIAH" nocase ascii wide

    condition:
        any of them
}