rule AtlasReaper
{
    meta:
        description = "Detection patterns for the tool 'AtlasReaper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AtlasReaper"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/AtlasReaper\.git/ nocase ascii wide
                        $string2 = /AtlasReaper\.exe/ nocase ascii wide
                        $string3 = "AtlasReaper-main" nocase ascii wide
                        $string4 = "werdhaihai/AtlasReaper" nocase ascii wide

    condition:
        any of them
}