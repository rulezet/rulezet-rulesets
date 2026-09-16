rule rule_BOFMask_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'BOFMask' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BOFMask"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_BOFMask_offensive_tool_keyword = /\/BOFMask\.git/ nocase ascii wide
                        $string2_BOFMask_offensive_tool_keyword = /\/bofmask\.h/ nocase ascii wide
                        $string3_BOFMask_offensive_tool_keyword = "BOFMask-main" nocase ascii wide
                        $string4_BOFMask_offensive_tool_keyword = /include.{0,1000}bofmask\.h/ nocase ascii wide
                        $string5_BOFMask_offensive_tool_keyword = "passthehashbrowns/BOFMask" nocase ascii wide

    condition:
        any of them
}