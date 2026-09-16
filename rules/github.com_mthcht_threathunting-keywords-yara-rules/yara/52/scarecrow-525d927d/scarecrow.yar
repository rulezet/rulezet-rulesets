rule ScareCrow
{
    meta:
        description = "Detection patterns for the tool 'ScareCrow' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ScareCrow"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-I\s.{0,1000}\.bin\s.{0,1000}\s\-Loader\sdll/ nocase ascii wide
                        $string2 = /\.\/ScareCrow\s\-/
                        $string3 = /\.\/ScareCrow/
                        $string4 = "optiv/ScareCrow" nocase ascii wide
                        $string5 = /ScareCrow\s.{0,1000}\-loader\s/ nocase ascii wide
                        $string6 = /ScareCrow.{0,1000}windows_amd64\.exe/ nocase ascii wide
                        $string7 = /ScareCrow\.go/ nocase ascii wide
                        $string8 = /ScareCrow_.{0,1000}_darwin_amd64/
                        $string9 = /ScareCrow_.{0,1000}_linux_amd64/
                        $string10 = /ScareCrow_.{0,1000}amd64/ nocase ascii wide
                        $string11 = /ScareCrow_checksums\.txt/ nocase ascii wide

    condition:
        any of them
}