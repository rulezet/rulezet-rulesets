rule rule_autobloody_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'autobloody' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "autobloody"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_autobloody_offensive_tool_keyword = " install autobloody"
                        $string2_autobloody_offensive_tool_keyword = /\/autobloody\.git/
                        $string3_autobloody_offensive_tool_keyword = "/autobloody/archive"
                        $string4_autobloody_offensive_tool_keyword = "AD Privesc Automation"
                        $string5_autobloody_offensive_tool_keyword = "autobloody -"
                        $string6_autobloody_offensive_tool_keyword = /autobloody\.py/
                        $string7_autobloody_offensive_tool_keyword = "autobloody-main"
                        $string8_autobloody_offensive_tool_keyword = "bolt://localhost:7687"
                        $string9_autobloody_offensive_tool_keyword = "CravateRouge/autobloody"
                        $string10_autobloody_offensive_tool_keyword = "Proxy bypass enabled for Neo4j connection"
                        $string11_autobloody_offensive_tool_keyword = /proxy_bypass\.py/

    condition:
        any of them
}