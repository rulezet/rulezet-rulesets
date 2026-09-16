rule rule_sprayhound_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'sprayhound' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sprayhound"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_sprayhound_offensive_tool_keyword = /\s\-\-neo4j\-host\s.{0,1000}\-\-neo4j\-port/ nocase ascii wide
                        $string2_sprayhound_offensive_tool_keyword = /\/sprayhound\.git/ nocase ascii wide
                        $string3_sprayhound_offensive_tool_keyword = /\/sprayhound\/.{0,1000}\.py/ nocase ascii wide
                        $string4_sprayhound_offensive_tool_keyword = "Hackndo/sprayhound" nocase ascii wide
                        $string5_sprayhound_offensive_tool_keyword = /neo4jconnection\.py/ nocase ascii wide
                        $string6_sprayhound_offensive_tool_keyword = /\-nh\s127\.0\.0\.1\s\-nP\s7687\s\-nu\sneo4j\s\-np\s/ nocase ascii wide
                        $string7_sprayhound_offensive_tool_keyword = "sprayhound -" nocase ascii wide
                        $string8_sprayhound_offensive_tool_keyword = /sprayhound\-master\.zip/ nocase ascii wide

    condition:
        any of them
}