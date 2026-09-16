rule SimplyEmail
{
    meta:
        description = "Detection patterns for the tool 'SimplyEmail' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SimplyEmail"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/SimplyEmail\.git/ nocase ascii wide
                        $string2 = /SimplyEmail\.py/ nocase ascii wide
                        $string3 = "SimplyEmail-master" nocase ascii wide
                        $string4 = "SimplySecurity/SimplyEmail" nocase ascii wide

    condition:
        any of them
}