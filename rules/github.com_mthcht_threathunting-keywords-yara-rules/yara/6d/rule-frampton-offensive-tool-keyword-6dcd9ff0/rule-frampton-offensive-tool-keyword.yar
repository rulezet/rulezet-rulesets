rule rule_frampton_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'frampton' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "frampton"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_frampton_offensive_tool_keyword = " --shellcode " nocase ascii wide
                        $string2_frampton_offensive_tool_keyword = /\.exe\s\-s\s.{0,1000}\\x.{0,1000}\\x.{0,1000}\\x/ nocase ascii wide
                        $string3_frampton_offensive_tool_keyword = /\.py\s\-f\s.{0,1000}\.exe\s\-e\s\-m\s4/ nocase ascii wide
                        $string4_frampton_offensive_tool_keyword = /_backdoor\.exe/ nocase ascii wide
                        $string5_frampton_offensive_tool_keyword = "Disabling ASLR " nocase ascii wide
                        $string6_frampton_offensive_tool_keyword = /frampton\.py/ nocase ascii wide
                        $string7_frampton_offensive_tool_keyword = "ins1gn1a/Frampton" nocase ascii wide

    condition:
        any of them
}