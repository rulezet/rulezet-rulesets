rule rule_SCCMVNC_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SCCMVNC' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SCCMVNC"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SCCMVNC_offensive_tool_keyword = /\/SCCMVNC\.git/ nocase ascii wide
                        $string2_SCCMVNC_offensive_tool_keyword = "b4d2e7159b1707d9355ac8699897c55441a25afebf66b4f47087b34d5e4994cb" nocase ascii wide
                        $string3_SCCMVNC_offensive_tool_keyword = "netero1010/SCCMVNC" nocase ascii wide
                        $string4_SCCMVNC_offensive_tool_keyword = /SCCMVNC\.exe/ nocase ascii wide

    condition:
        any of them
}