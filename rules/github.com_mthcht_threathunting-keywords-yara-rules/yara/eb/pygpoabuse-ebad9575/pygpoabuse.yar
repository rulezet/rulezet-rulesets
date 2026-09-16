rule pyGPOAbuse
{
    meta:
        description = "Detection patterns for the tool 'pyGPOAbuse' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pyGPOAbuse"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-hashes\slm\:nt\s\-gpo\-id\s.{0,1000}\s\-powershell\s/ nocase ascii wide
                        $string2 = /pygpoabuse\.py/ nocase ascii wide

    condition:
        any of them
}