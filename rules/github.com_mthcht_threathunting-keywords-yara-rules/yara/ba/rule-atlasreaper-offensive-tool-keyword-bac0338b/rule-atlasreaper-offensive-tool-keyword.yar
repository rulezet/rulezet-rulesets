rule rule_AtlasReaper_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AtlasReaper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AtlasReaper"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_AtlasReaper_offensive_tool_keyword = /\/AtlasReaper\.git/ nocase ascii wide
                        $string2_AtlasReaper_offensive_tool_keyword = /AtlasReaper\.exe/ nocase ascii wide
                        $string3_AtlasReaper_offensive_tool_keyword = "AtlasReaper-main" nocase ascii wide
                        $string4_AtlasReaper_offensive_tool_keyword = "werdhaihai/AtlasReaper" nocase ascii wide

    condition:
        any of them
}