rule rule_jecretz_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'jecretz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "jecretz"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_jecretz_offensive_tool_keyword = /\sjecretz\.py/ nocase ascii wide
                        $string2_jecretz_offensive_tool_keyword = /\/jecretz\.git/ nocase ascii wide
                        $string3_jecretz_offensive_tool_keyword = /\/jecretz\.py/ nocase ascii wide
                        $string4_jecretz_offensive_tool_keyword = /\[\+\]\sJecretz\sResults/ nocase ascii wide
                        $string5_jecretz_offensive_tool_keyword = /\\jecretz\.py/ nocase ascii wide
                        $string6_jecretz_offensive_tool_keyword = "c18c8abdaeacc30c7bdc46cf7565e5255aae8df8f34b7964ff09d35736d2816c" nocase ascii wide
                        $string7_jecretz_offensive_tool_keyword = "Jecretz, Jira Secrets Hunter" nocase ascii wide
                        $string8_jecretz_offensive_tool_keyword = /jira.{0,1000}\/rest\/issueNav\/1\/issueTable/ nocase ascii wide
                        $string9_jecretz_offensive_tool_keyword = "sahadnk72/jecretz" nocase ascii wide

    condition:
        any of them
}