rule pcunlocker
{
    meta:
        description = "Detection patterns for the tool 'pcunlocker' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pcunlocker"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "/download/pcunlocker" nocase ascii wide
                        $string2 = /\/pcunlocker\.iso/ nocase ascii wide
                        $string3 = /\/pcunlocker_trial\.zip/ nocase ascii wide
                        $string4 = /\\pcunlocker\.iso/ nocase ascii wide
                        $string5 = /\\pcunlocker_trial\.zip/ nocase ascii wide
                        $string6 = /pcunlocker_ent_trial\.zip/ nocase ascii wide

    condition:
        any of them
}