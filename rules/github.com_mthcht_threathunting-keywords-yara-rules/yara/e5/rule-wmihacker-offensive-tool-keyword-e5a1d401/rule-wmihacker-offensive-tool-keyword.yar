rule rule_WMIHACKER_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'WMIHACKER' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WMIHACKER"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_WMIHACKER_offensive_tool_keyword = /\sWMIHACKER\.vbs/ nocase ascii wide
                        $string2_WMIHACKER_offensive_tool_keyword = /\swmihacker_0\.4\.vbe/ nocase ascii wide
                        $string3_WMIHACKER_offensive_tool_keyword = /\sWMIHACKER_0\.6\.vbs/ nocase ascii wide
                        $string4_WMIHACKER_offensive_tool_keyword = /\/WMIHACKER\.git/ nocase ascii wide
                        $string5_WMIHACKER_offensive_tool_keyword = /\/WMIHACKER\.vbs/ nocase ascii wide
                        $string6_WMIHACKER_offensive_tool_keyword = /\\WMIHACKER\.vbs/ nocase ascii wide
                        $string7_WMIHACKER_offensive_tool_keyword = /\\wmihacker_0\.4\.vbe/ nocase ascii wide
                        $string8_WMIHACKER_offensive_tool_keyword = /\\WMIHACKER_0\.6\.vbs/ nocase ascii wide
                        $string9_WMIHACKER_offensive_tool_keyword = "131bacdddd51f0d5d869b63912606719cd8f7a8f5b5f4237cbdb5c2e22e2cba2" nocase ascii wide
                        $string10_WMIHACKER_offensive_tool_keyword = "iangshan@360RedTeam" nocase ascii wide
                        $string11_WMIHACKER_offensive_tool_keyword = "rootclay/WMIHACKER" nocase ascii wide
                        $string12_WMIHACKER_offensive_tool_keyword = "WMIHACKER : Login -> OK" nocase ascii wide

    condition:
        any of them
}