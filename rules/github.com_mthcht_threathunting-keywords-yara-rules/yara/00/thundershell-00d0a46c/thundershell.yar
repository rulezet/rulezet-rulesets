rule ThunderShell
{
    meta:
        description = "Detection patterns for the tool 'ThunderShell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ThunderShell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /data\/payloads\/stager\.ps1/ nocase ascii wide
                        $string2 = /mr\.un1k0d3r\@gmail\.com/ nocase ascii wide
                        $string3 = /\-out.{0,1000}\.exe\s\-r\:.{0,1000}System\.Drawing\.dll.{0,1000}System\.Management\.Automation.{0,1000}\.dll/ nocase ascii wide
                        $string4 = "PppEWCIgXbsepIwnuRIHtQLC" nocase ascii wide
                        $string5 = /scripts.{0,1000}Remote\-WmiExecute\./ nocase ascii wide
                        $string6 = /scripts.{0,1000}Search\-EventForUser\.ps1/ nocase ascii wide
                        $string7 = /ThunderShell\.git/ nocase ascii wide
                        $string8 = /ThunderShell\.py/ nocase ascii wide
                        $string9 = /ThunderShell\-master\.zip/ nocase ascii wide
                        $string10 = "YaWNdpwplLwycqWQDCyruhAFsYjWjnBA" nocase ascii wide

    condition:
        any of them
}