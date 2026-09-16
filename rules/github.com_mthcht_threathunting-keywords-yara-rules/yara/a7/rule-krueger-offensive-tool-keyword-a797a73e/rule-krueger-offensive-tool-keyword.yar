rule rule_Krueger_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Krueger' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Krueger"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Krueger_offensive_tool_keyword = /\/Krueger\.exe/ nocase ascii wide
                        $string2_Krueger_offensive_tool_keyword = /\/Krueger\.git/ nocase ascii wide
                        $string3_Krueger_offensive_tool_keyword = /\@_logangoins\\n\@hullabrian/ nocase ascii wide
                        $string4_Krueger_offensive_tool_keyword = /\\Krueger\.exe/ nocase ascii wide
                        $string5_Krueger_offensive_tool_keyword = "022E5A85-D732-4C5D-8CAD-A367139068D8" nocase ascii wide
                        $string6_Krueger_offensive_tool_keyword = "783c942169fb6fe2dd984470a470440dd10a1aec09a153759e8d78a95096a8e6" nocase ascii wide
                        $string7_Krueger_offensive_tool_keyword = /ADMIN\$\\\\System32\\\\CodeIntegrity\\\\SiPolicy\.p7b/ nocase ascii wide
                        $string8_Krueger_offensive_tool_keyword = /ADMIN\$\\System32\\CodeIntegrity\\SiPolicy\.p7b/ nocase ascii wide
                        $string9_Krueger_offensive_tool_keyword = /C\$\\\\Windows\\\\System32\\\\CodeIntegrity\\\\SiPolicy\.p7b/ nocase ascii wide
                        $string10_Krueger_offensive_tool_keyword = /C\$\\Windows\\System32\\CodeIntegrity\\SiPolicy\.p7b/ nocase ascii wide
                        $string11_Krueger_offensive_tool_keyword = "d2a4f52a9923336f119a52e531bbb1e66f18322fd8efa9af1a64b94f4d36dc97" nocase ascii wide
                        $string12_Krueger_offensive_tool_keyword = "d6bd37f7c1bcc7ea255d46c3f8f07e6fd754f566dd05682584def7c8ba0aebf9" nocase ascii wide
                        $string13_Krueger_offensive_tool_keyword = /Krueger\.SiPolicy\.p7b/ nocase ascii wide
                        $string14_Krueger_offensive_tool_keyword = "logangoins/Krueger" nocase ascii wide

    condition:
        any of them
}