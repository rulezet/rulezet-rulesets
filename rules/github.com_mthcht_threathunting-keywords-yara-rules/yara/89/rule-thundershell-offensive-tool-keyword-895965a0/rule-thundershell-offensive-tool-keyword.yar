rule rule_ThunderShell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ThunderShell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ThunderShell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ThunderShell_offensive_tool_keyword = /data\/payloads\/stager\.ps1/ nocase ascii wide
                        $string2_ThunderShell_offensive_tool_keyword = /mr\.un1k0d3r\@gmail\.com/ nocase ascii wide
                        $string3_ThunderShell_offensive_tool_keyword = /\-out.{0,1000}\.exe\s\-r\:.{0,1000}System\.Drawing\.dll.{0,1000}System\.Management\.Automation.{0,1000}\.dll/ nocase ascii wide
                        $string4_ThunderShell_offensive_tool_keyword = "PppEWCIgXbsepIwnuRIHtQLC" nocase ascii wide
                        $string5_ThunderShell_offensive_tool_keyword = /scripts.{0,1000}Remote\-WmiExecute\./ nocase ascii wide
                        $string6_ThunderShell_offensive_tool_keyword = /scripts.{0,1000}Search\-EventForUser\.ps1/ nocase ascii wide
                        $string7_ThunderShell_offensive_tool_keyword = /ThunderShell\.git/ nocase ascii wide
                        $string8_ThunderShell_offensive_tool_keyword = /ThunderShell\.py/ nocase ascii wide
                        $string9_ThunderShell_offensive_tool_keyword = /ThunderShell\-master\.zip/ nocase ascii wide
                        $string10_ThunderShell_offensive_tool_keyword = "YaWNdpwplLwycqWQDCyruhAFsYjWjnBA" nocase ascii wide

    condition:
        any of them
}