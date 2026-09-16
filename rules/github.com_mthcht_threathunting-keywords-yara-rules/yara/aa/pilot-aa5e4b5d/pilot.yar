rule PILOT
{
    meta:
        description = "Detection patterns for the tool 'PILOT' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PILOT"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\#\sAuthor\:\sDahvid\sSchloss\sa\.k\.a\sAPT\sBig\sDaddy/ nocase ascii wide
                        $string2 = /\/PILOT\/ATC\.py/ nocase ascii wide
                        $string3 = /\/PILOT\/PILOT\.ps1/ nocase ascii wide
                        $string4 = /\\PILOT\.ps1/ nocase ascii wide
                        $string5 = /\\PILOT\\ATC\.py/ nocase ascii wide
                        $string6 = "4870b4163315fa666dea8be03176d76aa215fe33187db45aca984e07b25ca827" nocase ascii wide
                        $string7 = "810950f1d775ffa916c75a85c79bb2a46f7c7250986be7748bfae90b04b33551" nocase ascii wide
                        $string8 = "Create a raw socket to listen for ICMP packets cause f scappy we don't need that shit" nocase ascii wide
                        $string9 = /dahvid\.schloss\@echeloncyber\.com/ nocase ascii wide
                        $string10 = "dahvidschloss/PILOT" nocase ascii wide
                        $string11 = /Listening\sfor\sincoming\sICMP\spackets\.\.\./ nocase ascii wide
                        $string12 = "run-pilot -targetIP " nocase ascii wide

    condition:
        any of them
}