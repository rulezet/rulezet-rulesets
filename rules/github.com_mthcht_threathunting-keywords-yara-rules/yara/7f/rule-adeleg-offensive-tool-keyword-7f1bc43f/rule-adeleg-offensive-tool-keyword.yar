rule rule_adeleg_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'adeleg' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adeleg"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_adeleg_offensive_tool_keyword = /\/ADeleg\.exe/ nocase ascii wide
                        $string2_adeleg_offensive_tool_keyword = /\/adeleg\.git/ nocase ascii wide
                        $string3_adeleg_offensive_tool_keyword = /\/adeleg\.pdb/ nocase ascii wide
                        $string4_adeleg_offensive_tool_keyword = /\\ADeleg\.exe/ nocase ascii wide
                        $string5_adeleg_offensive_tool_keyword = /\\adeleg\.pdb/ nocase ascii wide
                        $string6_adeleg_offensive_tool_keyword = /\\adeleg\\adeleg\\/ nocase ascii wide
                        $string7_adeleg_offensive_tool_keyword = /\\adeleg\\winldap\\/ nocase ascii wide
                        $string8_adeleg_offensive_tool_keyword = /\\adeleg\-main/ nocase ascii wide
                        $string9_adeleg_offensive_tool_keyword = /ADeleg\.exe\s\-/ nocase ascii wide
                        $string10_adeleg_offensive_tool_keyword = "mtth-bfft/adeleg" nocase ascii wide

    condition:
        any of them
}