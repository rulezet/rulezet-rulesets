rule secretfinder
{
    meta:
        description = "Detection patterns for the tool 'secretfinder' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "secretfinder"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.py\s.{0,1000}\s\-\-burp\s/ nocase ascii wide
                        $string2 = /\/SecretFinder\.git/ nocase ascii wide
                        $string3 = "BurpSuite-SecretFinder" nocase ascii wide
                        $string4 = "from burp import" nocase ascii wide
                        $string5 = "import IBurpExtender" nocase ascii wide
                        $string6 = "m4ll0k/SecretFinder" nocase ascii wide
                        $string7 = /SecretFinder\.py/ nocase ascii wide
                        $string8 = /SecretFinder\-master\.zip/ nocase ascii wide

    condition:
        any of them
}