rule rule_Crack_allDBs_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Crack-allDBs' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Crack-allDBs"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Crack_allDBs_offensive_tool_keyword = /Crack\-allDBs\.git/ nocase ascii wide
                        $string2_Crack_allDBs_offensive_tool_keyword = "Crack-allDBs-main" nocase ascii wide
                        $string3_Crack_allDBs_offensive_tool_keyword = /crack\-allDBs\-v1\.py/ nocase ascii wide
                        $string4_Crack_allDBs_offensive_tool_keyword = /crack\-allDBs\-v2\.py/ nocase ascii wide
                        $string5_Crack_allDBs_offensive_tool_keyword = "d3ckx1/Crack-allDBs" nocase ascii wide

    condition:
        any of them
}