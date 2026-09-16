rule rule_pcunlocker_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'pcunlocker' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pcunlocker"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_pcunlocker_greyware_tool_keyword = "/download/pcunlocker" nocase ascii wide
                        $string2_pcunlocker_greyware_tool_keyword = /\/pcunlocker\.iso/ nocase ascii wide
                        $string3_pcunlocker_greyware_tool_keyword = /\/pcunlocker_trial\.zip/ nocase ascii wide
                        $string4_pcunlocker_greyware_tool_keyword = /\\pcunlocker\.iso/ nocase ascii wide
                        $string5_pcunlocker_greyware_tool_keyword = /\\pcunlocker_trial\.zip/ nocase ascii wide
                        $string6_pcunlocker_greyware_tool_keyword = /pcunlocker_ent_trial\.zip/ nocase ascii wide

    condition:
        any of them
}