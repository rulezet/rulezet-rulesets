rule adfspray
{
    meta:
        description = "Detection patterns for the tool 'adfspray' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adfspray"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-t\s.{0,1000}https\:\/\/autodiscover\..{0,1000}\/autodiscover\/autodiscover\.xml.{0,1000}autodiscover/ nocase ascii wide
                        $string2 = /\s\-user\s.{0,1000}\s\-\-passwordlist\s/ nocase ascii wide
                        $string3 = "/ADFSpray" nocase ascii wide
                        $string4 = /\[.{0,1000}\]\sOverall\scompromised\saccounts\:\s/ nocase ascii wide
                        $string5 = /\[\+\]\sSeems\slike\sthe\screds\sare\svalid\:\s.{0,1000}\s\:\:\s.{0,1000}\son\s/ nocase ascii wide
                        $string6 = /\\ADFSpray/ nocase ascii wide
                        $string7 = /ADFSpray\.csv/ nocase ascii wide
                        $string8 = /adfspray\.git/ nocase ascii wide
                        $string9 = /ADFSpray\.py/ nocase ascii wide
                        $string10 = "Total number of passwords to test: " nocase ascii wide

    condition:
        any of them
}