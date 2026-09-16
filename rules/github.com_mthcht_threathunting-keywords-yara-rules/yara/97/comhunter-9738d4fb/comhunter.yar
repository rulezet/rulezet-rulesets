rule COMHunter
{
    meta:
        description = "Detection patterns for the tool 'COMHunter' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "COMHunter"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /COMHunter.{0,1000}\s\-inproc/ nocase ascii wide
                        $string2 = /COMHunter.{0,1000}\s\-localserver/ nocase ascii wide
                        $string3 = /COMHunter\.csproj/ nocase ascii wide
                        $string4 = /COMHunter\.exe/ nocase ascii wide
                        $string5 = /COMHunter\.sln/ nocase ascii wide
                        $string6 = /github.{0,1000}\/COMHunter\// nocase ascii wide

    condition:
        any of them
}