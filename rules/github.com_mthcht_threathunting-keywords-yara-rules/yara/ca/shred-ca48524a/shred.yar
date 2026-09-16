rule shred
{
    meta:
        description = "Detection patterns for the tool 'shred' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "shred"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /shred\s\$HISTFILE/ nocase ascii wide
                        $string2 = /shred\s\-n\s.{0,1000}\s\-u\s\-z\s.{0,1000}_history/ nocase ascii wide
                        $string3 = /shred\s\-n\s.{0,1000}\s\-z\s\-u\s.{0,1000}_history/ nocase ascii wide
                        $string4 = "shred --remove" nocase ascii wide
                        $string5 = /shred\s\-u\s\-n\s.{0,1000}\s\-z\s.{0,1000}_history/ nocase ascii wide
                        $string6 = /shred\s\-u\s\-z\s\-n\s.{0,1000}_history/ nocase ascii wide
                        $string7 = "shred -u" nocase ascii wide
                        $string8 = /shred\s\-z\s\-n\s.{0,1000}\s\-u\s.{0,1000}_history/ nocase ascii wide
                        $string9 = /shred\s\-z\s\-u\s\-n\s.{0,1000}_history/ nocase ascii wide
                        $string10 = "shred -z" nocase ascii wide
                        $string11 = "shred --zero" nocase ascii wide

    condition:
        any of them
}