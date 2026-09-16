rule TimeException
{
    meta:
        description = "Detection patterns for the tool 'TimeException' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TimeException"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.exe\s\-\-sample\-size\s1000\s\-\-mode\s0\s\-\-targets\sdirs\.txt/ nocase ascii wide
                        $string2 = /\.exe\s\-\-sample\-size\s1000\s\-\-mode\s1\s\-\-targets\sexts\.txt/ nocase ascii wide
                        $string3 = /\/TimeException\.exe/ nocase ascii wide
                        $string4 = /\/TimeException\.git/ nocase ascii wide
                        $string5 = /\\TimeException\.cpp/ nocase ascii wide
                        $string6 = /\\TimeException\.exe/ nocase ascii wide
                        $string7 = /\\TimeException\-main/ nocase ascii wide
                        $string8 = "30fb8b27a7636a8922aff3018b2b612bf224a17bf7a9c9f2f2a01d4f7754c522" nocase ascii wide
                        $string9 = "bananabr/TimeException" nocase ascii wide
                        $string10 = "c6a8d755e4764335fa9c5313c6ba641ac9a0228648065667f7d535457dbf0ceb" nocase ascii wide
                        $string11 = "e69f0324-3afb-485e-92c7-cb097ea47caf" nocase ascii wide

    condition:
        any of them
}