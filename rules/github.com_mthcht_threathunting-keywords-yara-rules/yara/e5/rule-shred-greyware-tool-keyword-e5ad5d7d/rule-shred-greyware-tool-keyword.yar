rule rule_shred_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'shred' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "shred"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_shred_greyware_tool_keyword = /shred\s\$HISTFILE/ nocase ascii wide
                        $string2_shred_greyware_tool_keyword = /shred\s\-n\s.{0,1000}\s\-u\s\-z\s.{0,1000}_history/ nocase ascii wide
                        $string3_shred_greyware_tool_keyword = /shred\s\-n\s.{0,1000}\s\-z\s\-u\s.{0,1000}_history/ nocase ascii wide
                        $string4_shred_greyware_tool_keyword = "shred --remove" nocase ascii wide
                        $string5_shred_greyware_tool_keyword = /shred\s\-u\s\-n\s.{0,1000}\s\-z\s.{0,1000}_history/ nocase ascii wide
                        $string6_shred_greyware_tool_keyword = /shred\s\-u\s\-z\s\-n\s.{0,1000}_history/ nocase ascii wide
                        $string7_shred_greyware_tool_keyword = "shred -u" nocase ascii wide
                        $string8_shred_greyware_tool_keyword = /shred\s\-z\s\-n\s.{0,1000}\s\-u\s.{0,1000}_history/ nocase ascii wide
                        $string9_shred_greyware_tool_keyword = /shred\s\-z\s\-u\s\-n\s.{0,1000}_history/ nocase ascii wide
                        $string10_shred_greyware_tool_keyword = "shred -z" nocase ascii wide
                        $string11_shred_greyware_tool_keyword = "shred --zero" nocase ascii wide

    condition:
        any of them
}