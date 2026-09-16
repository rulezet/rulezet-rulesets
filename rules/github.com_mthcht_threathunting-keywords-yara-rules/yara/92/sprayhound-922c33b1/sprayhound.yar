rule sprayhound
{
    meta:
        description = "Detection patterns for the tool 'sprayhound' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sprayhound"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-\-neo4j\-host\s.{0,1000}\-\-neo4j\-port/ nocase ascii wide
                        $string2 = /\/sprayhound\.git/ nocase ascii wide
                        $string3 = /\/sprayhound\/.{0,1000}\.py/ nocase ascii wide
                        $string4 = "Hackndo/sprayhound" nocase ascii wide
                        $string5 = /neo4jconnection\.py/ nocase ascii wide
                        $string6 = /\-nh\s127\.0\.0\.1\s\-nP\s7687\s\-nu\sneo4j\s\-np\s/ nocase ascii wide
                        $string7 = "sprayhound -" nocase ascii wide
                        $string8 = /sprayhound\-master\.zip/ nocase ascii wide

    condition:
        any of them
}