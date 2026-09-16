rule rule_secretfinder_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'secretfinder' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "secretfinder"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_secretfinder_offensive_tool_keyword = /\.py\s.{0,1000}\s\-\-burp\s/ nocase ascii wide
                        $string2_secretfinder_offensive_tool_keyword = /\/SecretFinder\.git/ nocase ascii wide
                        $string3_secretfinder_offensive_tool_keyword = "BurpSuite-SecretFinder" nocase ascii wide
                        $string4_secretfinder_offensive_tool_keyword = "from burp import" nocase ascii wide
                        $string5_secretfinder_offensive_tool_keyword = "import IBurpExtender" nocase ascii wide
                        $string6_secretfinder_offensive_tool_keyword = "m4ll0k/SecretFinder" nocase ascii wide
                        $string7_secretfinder_offensive_tool_keyword = /SecretFinder\.py/ nocase ascii wide
                        $string8_secretfinder_offensive_tool_keyword = /SecretFinder\-master\.zip/ nocase ascii wide

    condition:
        any of them
}