rule autobloody
{
    meta:
        description = "Detection patterns for the tool 'autobloody' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "autobloody"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " install autobloody"
                        $string2 = /\/autobloody\.git/
                        $string3 = "/autobloody/archive"
                        $string4 = "AD Privesc Automation"
                        $string5 = "autobloody -"
                        $string6 = /autobloody\.py/
                        $string7 = "autobloody-main"
                        $string8 = "bolt://localhost:7687"
                        $string9 = "CravateRouge/autobloody"
                        $string10 = "Proxy bypass enabled for Neo4j connection"
                        $string11 = /proxy_bypass\.py/

    condition:
        any of them
}