rule goZulipC2
{
    meta:
        description = "Detection patterns for the tool 'goZulipC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "goZulipC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/AntiSandbox\.go/ nocase ascii wide
                        $string2 = /\/goZulipC2\.git/ nocase ascii wide
                        $string3 = /\\AntiSandbox\.go/ nocase ascii wide
                        $string4 = /\\goZulipC2/ nocase ascii wide
                        $string5 = /goZulipC2\.go/ nocase ascii wide
                        $string6 = "goZulipC2-main" nocase ascii wide
                        $string7 = "n1k7l4i/goZulipC2" nocase ascii wide

    condition:
        any of them
}