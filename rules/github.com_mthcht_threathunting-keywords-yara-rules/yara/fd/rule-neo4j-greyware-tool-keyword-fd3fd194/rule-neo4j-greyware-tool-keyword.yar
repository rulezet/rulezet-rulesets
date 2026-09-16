rule rule_Neo4j_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Neo4j' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Neo4j"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Neo4j_greyware_tool_keyword = /MATCH\s\(c\:Computer\s\{unconsraineddelegation\:true\}\)\sRETURN\sc/ nocase ascii wide
                        $string2_Neo4j_greyware_tool_keyword = /MATCH\s\(c\:Computer\).{0,1000}\(t\:Computer\).{0,1000}\s.{0,1000}\-\[\:AllowedToDelegate\].{0,1000}\sreturn\sp/ nocase ascii wide
                        $string3_Neo4j_greyware_tool_keyword = /MATCH\sp\=\(u\:User\)\-\[\:SQLAdmin\].{0,1000}\(c\:Computer\)\sreturn\sp/ nocase ascii wide
                        $string4_Neo4j_greyware_tool_keyword = "neo4j start" nocase ascii wide

    condition:
        any of them
}