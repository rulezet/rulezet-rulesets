rule updog
{
    meta:
        description = "Detection patterns for the tool 'updog' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "updog"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/updog\-.{0,1000}\.tar\.gz/ nocase ascii wide
                        $string2 = /\/updog\.git/ nocase ascii wide
                        $string3 = "/updog/archive/updog-" nocase ascii wide
                        $string4 = /\\updog\-master\\/ nocase ascii wide
                        $string5 = /pip.{0,1000}\sinstall\supdog/ nocase ascii wide
                        $string6 = "sc0tfree/updog" nocase ascii wide
                        $string7 = "updog --" nocase ascii wide
                        $string8 = "updog -d /" nocase ascii wide
                        $string9 = "updog -p " nocase ascii wide
                        $string10 = /updog\-master\.zip/ nocase ascii wide

    condition:
        any of them
}