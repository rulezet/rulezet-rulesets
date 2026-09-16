rule rule_EmailAll_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'EmailAll' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EmailAll"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_EmailAll_offensive_tool_keyword = /\s\-\-domains\s\.\/domains\.txt\srun/
                        $string2_EmailAll_offensive_tool_keyword = /\semailall\.py/ nocase ascii wide
                        $string3_EmailAll_offensive_tool_keyword = /\/EmailAll\.git/ nocase ascii wide
                        $string4_EmailAll_offensive_tool_keyword = /\/emailall\.py/ nocase ascii wide
                        $string5_EmailAll_offensive_tool_keyword = /\\emailall\.py/ nocase ascii wide
                        $string6_EmailAll_offensive_tool_keyword = /emailall\.py\s\-/ nocase ascii wide
                        $string7_EmailAll_offensive_tool_keyword = /emailall\.py\scheck/ nocase ascii wide
                        $string8_EmailAll_offensive_tool_keyword = /EmailAll\-master\./ nocase ascii wide
                        $string9_EmailAll_offensive_tool_keyword = "Taonn/EmailAll" nocase ascii wide

    condition:
        any of them
}