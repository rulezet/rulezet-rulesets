rule rule_PILOT_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PILOT' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PILOT"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PILOT_offensive_tool_keyword = /\#\sAuthor\:\sDahvid\sSchloss\sa\.k\.a\sAPT\sBig\sDaddy/ nocase ascii wide
                        $string2_PILOT_offensive_tool_keyword = /\/PILOT\/ATC\.py/ nocase ascii wide
                        $string3_PILOT_offensive_tool_keyword = /\/PILOT\/PILOT\.ps1/ nocase ascii wide
                        $string4_PILOT_offensive_tool_keyword = /\\PILOT\.ps1/ nocase ascii wide
                        $string5_PILOT_offensive_tool_keyword = /\\PILOT\\ATC\.py/ nocase ascii wide
                        $string6_PILOT_offensive_tool_keyword = "4870b4163315fa666dea8be03176d76aa215fe33187db45aca984e07b25ca827" nocase ascii wide
                        $string7_PILOT_offensive_tool_keyword = "810950f1d775ffa916c75a85c79bb2a46f7c7250986be7748bfae90b04b33551" nocase ascii wide
                        $string8_PILOT_offensive_tool_keyword = "Create a raw socket to listen for ICMP packets cause f scappy we don't need that shit" nocase ascii wide
                        $string9_PILOT_offensive_tool_keyword = /dahvid\.schloss\@echeloncyber\.com/ nocase ascii wide
                        $string10_PILOT_offensive_tool_keyword = "dahvidschloss/PILOT" nocase ascii wide
                        $string11_PILOT_offensive_tool_keyword = /Listening\sfor\sincoming\sICMP\spackets\.\.\./ nocase ascii wide
                        $string12_PILOT_offensive_tool_keyword = "run-pilot -targetIP " nocase ascii wide

    condition:
        any of them
}