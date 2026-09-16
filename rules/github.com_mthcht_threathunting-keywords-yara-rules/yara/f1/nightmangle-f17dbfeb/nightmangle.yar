rule Nightmangle
{
    meta:
        description = "Detection patterns for the tool 'Nightmangle' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Nightmangle"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/imperun\s.{0,1000}\s.{0,1000}cmd\.exe\s\/c\swhoami/ nocase ascii wide
                        $string2 = /\/Nightmangle\.git/ nocase ascii wide
                        $string3 = /\[\+\]\sBof\sreplay\:/ nocase ascii wide
                        $string4 = /\[\+\]\sSeImpersonatePrivilege\senabled/ nocase ascii wide
                        $string5 = "1N73LL1G3NC3x/Nightmangle" nocase ascii wide
                        $string6 = "BeaconInjectProcess" nocase ascii wide
                        $string7 = "BeaconInjectTemporaryProcess" nocase ascii wide
                        $string8 = "Nightmangle-master" nocase ascii wide

    condition:
        any of them
}