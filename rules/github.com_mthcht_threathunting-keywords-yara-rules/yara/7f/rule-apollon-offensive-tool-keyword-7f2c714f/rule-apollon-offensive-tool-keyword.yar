rule rule_apollon_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'apollon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "apollon"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_apollon_offensive_tool_keyword = "/apollon-all-x64" nocase ascii wide
                        $string2_apollon_offensive_tool_keyword = /\/apollon\-main\.zip/ nocase ascii wide
                        $string3_apollon_offensive_tool_keyword = "/apollon-selective-x64" nocase ascii wide
                        $string4_apollon_offensive_tool_keyword = /\[\-\]\sSeems\slike\swe\skilled\sauditd\.\sOoopsie\s\:D/ nocase ascii wide
                        $string5_apollon_offensive_tool_keyword = /\[\+\]\sauditd\spatched\ssuccessfully/ nocase ascii wide
                        $string6_apollon_offensive_tool_keyword = "codewhitesec/apollon" nocase ascii wide

    condition:
        any of them
}