rule WMEye
{
    meta:
        description = "Detection patterns for the tool 'WMEye' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WMEye"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/WMEye\.git/ nocase ascii wide
                        $string2 = "/wmeye/" nocase ascii wide
                        $string3 = /\[X\]\sShellCode\sProperty\sCreated/ nocase ascii wide
                        $string4 = /\[X\]\sUploading\sShellcode\sinto\starget/ nocase ascii wide
                        $string5 = /\\wmeye\.csproj/ nocase ascii wide
                        $string6 = /\\wmeye\.pdb/ nocase ascii wide
                        $string7 = "080de56a40e4ff15b0157da0224988a36f3e7c2347d58824ab3880f338d3eaec" nocase ascii wide
                        $string8 = "928120DC-5275-4806-B99B-12D67B710DC0" nocase ascii wide
                        $string9 = "namespace WmEye" nocase ascii wide
                        $string10 = "OiCAAAAYInlMcBki1Awi1IMi1IUi3IoD7dKJjH/rDxhfAIsIMHPDQHH4vJSV4tSEItKPItMEXjjSAHRUYtZIAHTi0kY4zpJizSLAdYx" nocase ascii wide
                        $string11 = "public class WmEye" nocase ascii wide
                        $string12 = "pwn1sher/WMEye" nocase ascii wide
                        $string13 = /wmeye\.csproj/ nocase ascii wide
                        $string14 = /wmeye\.exe\s/ nocase ascii wide
                        $string15 = /wmeye\.sln/ nocase ascii wide

    condition:
        any of them
}