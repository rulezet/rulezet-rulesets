rule Windows_Privilege_Escalation
{
    meta:
        description = "Detection patterns for the tool 'Windows-Privilege-Escalation' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Windows-Privilege-Escalation"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\\Users\\Public\\nc\.exe/ nocase ascii wide
                        $string2 = /CopyAndPasteEnum\.bat/ nocase ascii wide
                        $string3 = /CopyAndPasteFileDownloader\.bat/ nocase ascii wide
                        $string4 = /cscript\sdl\.vbs\s.{0,1000}http.{0,1000}\/.{0,1000}\.zip.{0,1000}\.zip/ nocase ascii wide
                        $string5 = /ReverseShell\.ps1/ nocase ascii wide
                        $string6 = /windows_recon\.bat/ nocase ascii wide
                        $string7 = "windows-privesc-check" nocase ascii wide
                        $string8 = "Windows-Privilege-Escalation" nocase ascii wide
                        $string9 = /winreconstreamline\.bat/ nocase ascii wide

    condition:
        any of them
}