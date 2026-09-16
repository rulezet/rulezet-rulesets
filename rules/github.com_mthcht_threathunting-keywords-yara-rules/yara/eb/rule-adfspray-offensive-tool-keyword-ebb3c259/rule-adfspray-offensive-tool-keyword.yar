rule rule_adfspray_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'adfspray' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adfspray"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_adfspray_offensive_tool_keyword = /\s\-t\s.{0,1000}https\:\/\/autodiscover\..{0,1000}\/autodiscover\/autodiscover\.xml.{0,1000}autodiscover/ nocase ascii wide
                        $string2_adfspray_offensive_tool_keyword = /\s\-user\s.{0,1000}\s\-\-passwordlist\s/ nocase ascii wide
                        $string3_adfspray_offensive_tool_keyword = "/ADFSpray" nocase ascii wide
                        $string4_adfspray_offensive_tool_keyword = /\[.{0,1000}\]\sOverall\scompromised\saccounts\:\s/ nocase ascii wide
                        $string5_adfspray_offensive_tool_keyword = /\[\+\]\sSeems\slike\sthe\screds\sare\svalid\:\s.{0,1000}\s\:\:\s.{0,1000}\son\s/ nocase ascii wide
                        $string6_adfspray_offensive_tool_keyword = /\\ADFSpray/ nocase ascii wide
                        $string7_adfspray_offensive_tool_keyword = /ADFSpray\.csv/ nocase ascii wide
                        $string8_adfspray_offensive_tool_keyword = /adfspray\.git/ nocase ascii wide
                        $string9_adfspray_offensive_tool_keyword = /ADFSpray\.py/ nocase ascii wide
                        $string10_adfspray_offensive_tool_keyword = "Total number of passwords to test: " nocase ascii wide

    condition:
        any of them
}