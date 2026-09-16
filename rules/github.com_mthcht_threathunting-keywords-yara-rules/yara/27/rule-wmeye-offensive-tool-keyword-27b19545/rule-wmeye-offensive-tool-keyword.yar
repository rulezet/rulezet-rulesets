rule rule_WMEye_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'WMEye' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WMEye"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_WMEye_offensive_tool_keyword = /\/WMEye\.git/ nocase ascii wide
                        $string2_WMEye_offensive_tool_keyword = "/wmeye/" nocase ascii wide
                        $string3_WMEye_offensive_tool_keyword = /\[X\]\sShellCode\sProperty\sCreated/ nocase ascii wide
                        $string4_WMEye_offensive_tool_keyword = /\[X\]\sUploading\sShellcode\sinto\starget/ nocase ascii wide
                        $string5_WMEye_offensive_tool_keyword = /\\wmeye\.csproj/ nocase ascii wide
                        $string6_WMEye_offensive_tool_keyword = /\\wmeye\.pdb/ nocase ascii wide
                        $string7_WMEye_offensive_tool_keyword = "080de56a40e4ff15b0157da0224988a36f3e7c2347d58824ab3880f338d3eaec" nocase ascii wide
                        $string8_WMEye_offensive_tool_keyword = "928120DC-5275-4806-B99B-12D67B710DC0" nocase ascii wide
                        $string9_WMEye_offensive_tool_keyword = "namespace WmEye" nocase ascii wide
                        $string10_WMEye_offensive_tool_keyword = "OiCAAAAYInlMcBki1Awi1IMi1IUi3IoD7dKJjH/rDxhfAIsIMHPDQHH4vJSV4tSEItKPItMEXjjSAHRUYtZIAHTi0kY4zpJizSLAdYx" nocase ascii wide
                        $string11_WMEye_offensive_tool_keyword = "public class WmEye" nocase ascii wide
                        $string12_WMEye_offensive_tool_keyword = "pwn1sher/WMEye" nocase ascii wide
                        $string13_WMEye_offensive_tool_keyword = /wmeye\.csproj/ nocase ascii wide
                        $string14_WMEye_offensive_tool_keyword = /wmeye\.exe\s/ nocase ascii wide
                        $string15_WMEye_offensive_tool_keyword = /wmeye\.sln/ nocase ascii wide

    condition:
        any of them
}