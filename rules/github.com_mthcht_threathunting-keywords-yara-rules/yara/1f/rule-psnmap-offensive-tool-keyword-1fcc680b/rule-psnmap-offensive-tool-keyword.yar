rule rule_Psnmap_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Psnmap' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Psnmap"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Psnmap_offensive_tool_keyword = /\sPSnmap\.ps1/ nocase ascii wide
                        $string2_Psnmap_offensive_tool_keyword = /\/PSnmap\.git/ nocase ascii wide
                        $string3_Psnmap_offensive_tool_keyword = /\/PSnmap\.ps1/ nocase ascii wide
                        $string4_Psnmap_offensive_tool_keyword = /\/PSnmap\.psd1/ nocase ascii wide
                        $string5_Psnmap_offensive_tool_keyword = /\/PSnmap\.psm1/ nocase ascii wide
                        $string6_Psnmap_offensive_tool_keyword = /\\PSnmap\.ps1/ nocase ascii wide
                        $string7_Psnmap_offensive_tool_keyword = /\\PSnmap\.psd1/ nocase ascii wide
                        $string8_Psnmap_offensive_tool_keyword = /\\PSnmap\.psm1/ nocase ascii wide
                        $string9_Psnmap_offensive_tool_keyword = "5e60bc27d24e7a5b641fa59ee55002dae44ce9dde494df9783a9aa002455c6d2" nocase ascii wide
                        $string10_Psnmap_offensive_tool_keyword = /Add\-Member\s\-MemberType\sNoteProperty\s\-Name\sPing\s\-Value\s\(Test\-Connection\s\-ComputerName\s.{0,1000}\s\-Quiet\s\-Count\s1\)\s\-Force/ nocase ascii wide
                        $string11_Psnmap_offensive_tool_keyword = "ba20280d3b1e1ba3539232ee1b32c6071958811da1cb6716aeb33480977da408" nocase ascii wide
                        $string12_Psnmap_offensive_tool_keyword = "be09f42e9225e82fe619a700b93d33e3bf0603266b7865d45a786630d4303aa7" nocase ascii wide
                        $string13_Psnmap_offensive_tool_keyword = "EliteLoser/PSnmap" nocase ascii wide
                        $string14_Psnmap_offensive_tool_keyword = "Install-Module -Name PSnmap -Scope " nocase ascii wide
                        $string15_Psnmap_offensive_tool_keyword = "Invoke-Psnmap" nocase ascii wide

    condition:
        any of them
}