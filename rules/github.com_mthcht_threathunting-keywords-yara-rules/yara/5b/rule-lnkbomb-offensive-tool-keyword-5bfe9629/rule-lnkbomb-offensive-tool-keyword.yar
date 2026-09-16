rule rule_lnkbomb_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'lnkbomb' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "lnkbomb"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_lnkbomb_offensive_tool_keyword = /\slnkbomb\.py/ nocase ascii wide
                        $string2_lnkbomb_offensive_tool_keyword = /\/lnkbomb\.git/ nocase ascii wide
                        $string3_lnkbomb_offensive_tool_keyword = /\/lnkbomb\.py/ nocase ascii wide
                        $string4_lnkbomb_offensive_tool_keyword = /\[warn\]\sYou\seither\sfat\sfingered\sthis\sor\ssomething\selse\.\sEither\sway/ nocase ascii wide
                        $string5_lnkbomb_offensive_tool_keyword = /\\lnkbomb\.py/ nocase ascii wide
                        $string6_lnkbomb_offensive_tool_keyword = /\\lnkbomb\-1\.0\\/ nocase ascii wide
                        $string7_lnkbomb_offensive_tool_keyword = "dievus/lnkbomb" nocase ascii wide
                        $string8_lnkbomb_offensive_tool_keyword = /lnkbomb\.py\s/ nocase ascii wide
                        $string9_lnkbomb_offensive_tool_keyword = /lnkbomb\-1\.0\.zip/ nocase ascii wide
                        $string10_lnkbomb_offensive_tool_keyword = "Malicious Shortcut Generator" nocase ascii wide

    condition:
        any of them
}