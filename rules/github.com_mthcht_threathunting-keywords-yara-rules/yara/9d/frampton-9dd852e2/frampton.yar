rule frampton
{
    meta:
        description = "Detection patterns for the tool 'frampton' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "frampton"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " --shellcode " nocase ascii wide
                        $string2 = /\.exe\s\-s\s.{0,1000}\\x.{0,1000}\\x.{0,1000}\\x/ nocase ascii wide
                        $string3 = /\.py\s\-f\s.{0,1000}\.exe\s\-e\s\-m\s4/ nocase ascii wide
                        $string4 = /_backdoor\.exe/ nocase ascii wide
                        $string5 = "Disabling ASLR " nocase ascii wide
                        $string6 = /frampton\.py/ nocase ascii wide
                        $string7 = "ins1gn1a/Frampton" nocase ascii wide

    condition:
        any of them
}