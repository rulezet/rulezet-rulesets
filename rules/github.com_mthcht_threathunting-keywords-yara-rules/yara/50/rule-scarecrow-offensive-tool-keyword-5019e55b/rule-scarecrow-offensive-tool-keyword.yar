rule rule_ScareCrow_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ScareCrow' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ScareCrow"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ScareCrow_offensive_tool_keyword = /\s\-I\s.{0,1000}\.bin\s.{0,1000}\s\-Loader\sdll/ nocase ascii wide
                        $string2_ScareCrow_offensive_tool_keyword = /\.\/ScareCrow\s\-/
                        $string3_ScareCrow_offensive_tool_keyword = /\.\/ScareCrow/
                        $string4_ScareCrow_offensive_tool_keyword = "optiv/ScareCrow" nocase ascii wide
                        $string5_ScareCrow_offensive_tool_keyword = /ScareCrow\s.{0,1000}\-loader\s/ nocase ascii wide
                        $string6_ScareCrow_offensive_tool_keyword = /ScareCrow.{0,1000}windows_amd64\.exe/ nocase ascii wide
                        $string7_ScareCrow_offensive_tool_keyword = /ScareCrow\.go/ nocase ascii wide
                        $string8_ScareCrow_offensive_tool_keyword = /ScareCrow_.{0,1000}_darwin_amd64/
                        $string9_ScareCrow_offensive_tool_keyword = /ScareCrow_.{0,1000}_linux_amd64/
                        $string10_ScareCrow_offensive_tool_keyword = /ScareCrow_.{0,1000}amd64/ nocase ascii wide
                        $string11_ScareCrow_offensive_tool_keyword = /ScareCrow_checksums\.txt/ nocase ascii wide

    condition:
        any of them
}