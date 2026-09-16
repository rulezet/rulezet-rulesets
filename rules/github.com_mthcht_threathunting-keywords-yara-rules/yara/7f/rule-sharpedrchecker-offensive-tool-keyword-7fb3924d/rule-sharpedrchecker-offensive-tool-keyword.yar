rule rule_SharpEDRChecker_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpEDRChecker' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpEDRChecker"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpEDRChecker_offensive_tool_keyword = " SharpEDRChecker" nocase ascii wide
                        $string2_SharpEDRChecker_offensive_tool_keyword = /\/SharpEDRChecker\-.{0,1000}\.zip/ nocase ascii wide
                        $string3_SharpEDRChecker_offensive_tool_keyword = /\/SharpEDRChecker\.git/ nocase ascii wide
                        $string4_SharpEDRChecker_offensive_tool_keyword = "/SharpEDRChecker/" nocase ascii wide
                        $string5_SharpEDRChecker_offensive_tool_keyword = /\[\!\]\[\!\]\[\!\]\sChecking\sDirectories\s\[\!\]\[\!\]\[\!\]/ nocase ascii wide
                        $string6_SharpEDRChecker_offensive_tool_keyword = /\[\!\]\[\!\]\[\!\]\sChecking\sdrivers\s\[\!\]\[\!\]\[\!\]/ nocase ascii wide
                        $string7_SharpEDRChecker_offensive_tool_keyword = /\[\!\]\[\!\]\[\!\]\sChecking\smodules\sloaded\sin\syour\scurrent\sprocess\s\[\!\]\[\!\]\[\!\]/ nocase ascii wide
                        $string8_SharpEDRChecker_offensive_tool_keyword = /\[\!\]\[\!\]\[\!\]\sChecking\sServices\s\[\!\]\[\!\]\[\!\]/ nocase ascii wide
                        $string9_SharpEDRChecker_offensive_tool_keyword = /\[\!\]\[\!\]\[\!\]\sEDR\sChecks\sComplete\s\[\!\]\[\!\]\[\!\]/ nocase ascii wide
                        $string10_SharpEDRChecker_offensive_tool_keyword = /\[\!\]\[\!\]\[\!\]\sWelcome\sto\sSharpEDRChecker\sby\s\@PwnDexter\s\[\!\]\[\!\]\[\!\]/ nocase ascii wide
                        $string11_SharpEDRChecker_offensive_tool_keyword = /\\SharpEDRChecker\-.{0,1000}\.zip/ nocase ascii wide
                        $string12_SharpEDRChecker_offensive_tool_keyword = /\\SharpEDRChecker\.cs/ nocase ascii wide
                        $string13_SharpEDRChecker_offensive_tool_keyword = /\\SharpEDRChecker\.sln/ nocase ascii wide
                        $string14_SharpEDRChecker_offensive_tool_keyword = /\\SharpEDRChecker\\/ nocase ascii wide
                        $string15_SharpEDRChecker_offensive_tool_keyword = "14e8721290b9457ec4c641c48aaa111df18eeed8e1c208da18666d3f3dd8e2ff" nocase ascii wide
                        $string16_SharpEDRChecker_offensive_tool_keyword = "BDFEE233-3FED-42E5-AA64-492EB2AC7047" nocase ascii wide
                        $string17_SharpEDRChecker_offensive_tool_keyword = "e3038dfa23e4c4707e73f5b4a214fe35796b805ef213e0e84da1e20cd5643fa5" nocase ascii wide
                        $string18_SharpEDRChecker_offensive_tool_keyword = "Invoke-EDRChecker" nocase ascii wide
                        $string19_SharpEDRChecker_offensive_tool_keyword = "PwnDexter/SharpEDRChecker" nocase ascii wide
                        $string20_SharpEDRChecker_offensive_tool_keyword = /SharpEDRChecker\.exe/ nocase ascii wide
                        $string21_SharpEDRChecker_offensive_tool_keyword = /SharpEDRChecker\.Program/ nocase ascii wide
                        $string22_SharpEDRChecker_offensive_tool_keyword = "SharpEDRChecker/releases" nocase ascii wide

    condition:
        any of them
}