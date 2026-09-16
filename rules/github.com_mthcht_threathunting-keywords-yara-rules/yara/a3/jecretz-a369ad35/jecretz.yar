rule jecretz
{
    meta:
        description = "Detection patterns for the tool 'jecretz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "jecretz"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sjecretz\.py/ nocase ascii wide
                        $string2 = /\/jecretz\.git/ nocase ascii wide
                        $string3 = /\/jecretz\.py/ nocase ascii wide
                        $string4 = /\[\+\]\sJecretz\sResults/ nocase ascii wide
                        $string5 = /\\jecretz\.py/ nocase ascii wide
                        $string6 = "c18c8abdaeacc30c7bdc46cf7565e5255aae8df8f34b7964ff09d35736d2816c" nocase ascii wide
                        $string7 = "Jecretz, Jira Secrets Hunter" nocase ascii wide
                        $string8 = /jira.{0,1000}\/rest\/issueNav\/1\/issueTable/ nocase ascii wide
                        $string9 = "sahadnk72/jecretz" nocase ascii wide

    condition:
        any of them
}