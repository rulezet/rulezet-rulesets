rule lnkbomb
{
    meta:
        description = "Detection patterns for the tool 'lnkbomb' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "lnkbomb"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\slnkbomb\.py/ nocase ascii wide
                        $string2 = /\/lnkbomb\.git/ nocase ascii wide
                        $string3 = /\/lnkbomb\.py/ nocase ascii wide
                        $string4 = /\[warn\]\sYou\seither\sfat\sfingered\sthis\sor\ssomething\selse\.\sEither\sway/ nocase ascii wide
                        $string5 = /\\lnkbomb\.py/ nocase ascii wide
                        $string6 = /\\lnkbomb\-1\.0\\/ nocase ascii wide
                        $string7 = "dievus/lnkbomb" nocase ascii wide
                        $string8 = /lnkbomb\.py\s/ nocase ascii wide
                        $string9 = /lnkbomb\-1\.0\.zip/ nocase ascii wide
                        $string10 = "Malicious Shortcut Generator" nocase ascii wide

    condition:
        any of them
}