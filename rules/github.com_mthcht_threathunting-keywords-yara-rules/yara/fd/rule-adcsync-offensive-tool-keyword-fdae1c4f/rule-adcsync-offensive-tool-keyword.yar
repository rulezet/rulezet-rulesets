rule rule_adcsync_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'adcsync' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adcsync"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_adcsync_offensive_tool_keyword = /\sadcsync\.py/ nocase ascii wide
                        $string2_adcsync_offensive_tool_keyword = /\/adcsync\.git/ nocase ascii wide
                        $string3_adcsync_offensive_tool_keyword = /\/adcsync\.py/ nocase ascii wide
                        $string4_adcsync_offensive_tool_keyword = /\\adcsync\.py/ nocase ascii wide
                        $string5_adcsync_offensive_tool_keyword = /adcsync\.py\s\-/ nocase ascii wide
                        $string6_adcsync_offensive_tool_keyword = /Certipy\snot\sfound\.\sPlease\sinstall\sCertipy\sbefore\srunning\sADCSync/ nocase ascii wide
                        $string7_adcsync_offensive_tool_keyword = /certipy\sreq\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-target\-ip\s.{0,1000}\s\-dc\-ip\s.{0,1000}\s\-ca\s/ nocase ascii wide
                        $string8_adcsync_offensive_tool_keyword = "JPG0mez/ADCSync" nocase ascii wide

    condition:
        any of them
}