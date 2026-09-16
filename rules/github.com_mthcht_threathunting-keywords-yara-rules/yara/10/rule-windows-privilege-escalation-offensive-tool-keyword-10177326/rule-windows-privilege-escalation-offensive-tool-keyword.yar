rule rule_Windows_Privilege_Escalation_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Windows-Privilege-Escalation' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Windows-Privilege-Escalation"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Windows_Privilege_Escalation_offensive_tool_keyword = /\\Users\\Public\\nc\.exe/ nocase ascii wide
                        $string2_Windows_Privilege_Escalation_offensive_tool_keyword = /CopyAndPasteEnum\.bat/ nocase ascii wide
                        $string3_Windows_Privilege_Escalation_offensive_tool_keyword = /CopyAndPasteFileDownloader\.bat/ nocase ascii wide
                        $string4_Windows_Privilege_Escalation_offensive_tool_keyword = /cscript\sdl\.vbs\s.{0,1000}http.{0,1000}\/.{0,1000}\.zip.{0,1000}\.zip/ nocase ascii wide
                        $string5_Windows_Privilege_Escalation_offensive_tool_keyword = /ReverseShell\.ps1/ nocase ascii wide
                        $string6_Windows_Privilege_Escalation_offensive_tool_keyword = /windows_recon\.bat/ nocase ascii wide
                        $string7_Windows_Privilege_Escalation_offensive_tool_keyword = "windows-privesc-check" nocase ascii wide
                        $string8_Windows_Privilege_Escalation_offensive_tool_keyword = "Windows-Privilege-Escalation" nocase ascii wide
                        $string9_Windows_Privilege_Escalation_offensive_tool_keyword = /winreconstreamline\.bat/ nocase ascii wide

    condition:
        any of them
}