rule shhmon
{
    meta:
        description = "Detection patterns for the tool 'shhmon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "shhmon"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/Shhmon/" nocase ascii wide
                        $string2 = /\\Shhmon\./ nocase ascii wide
                        $string3 = "matterpreter/Shhmon" nocase ascii wide
                        $string4 = /Shhmon\.csproj/ nocase ascii wide
                        $string5 = /Shhmon\.exe/ nocase ascii wide
                        $string6 = /Shhmon\.git/ nocase ascii wide
                        $string7 = /sshmon.{0,1000}hunt/ nocase ascii wide
                        $string8 = /sshmon.{0,1000}kill/ nocase ascii wide

    condition:
        any of them
}