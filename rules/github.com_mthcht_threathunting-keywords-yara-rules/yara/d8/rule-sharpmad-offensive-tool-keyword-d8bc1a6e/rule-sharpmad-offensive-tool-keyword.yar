rule rule_Sharpmad_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Sharpmad' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Sharpmad"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Sharpmad_offensive_tool_keyword = /\/Sharpmad\.exe/ nocase ascii wide
                        $string2_Sharpmad_offensive_tool_keyword = /\\Sharpmad\.exe/ nocase ascii wide
                        $string3_Sharpmad_offensive_tool_keyword = /\\Sharpmad\.pdb/ nocase ascii wide
                        $string4_Sharpmad_offensive_tool_keyword = ">Sharpmad<" nocase ascii wide

    condition:
        any of them
}