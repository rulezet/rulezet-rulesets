rule TokenUniverse
{
    meta:
        description = "Detection patterns for the tool 'TokenUniverse' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TokenUniverse"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sTokenUniverse\.zip/ nocase ascii wide
                        $string2 = /\/TokenUniverse\.git/ nocase ascii wide
                        $string3 = /\/TokenUniverse\.zip/ nocase ascii wide
                        $string4 = /\\TokenUniverse\.zip/ nocase ascii wide
                        $string5 = /\\TokenUniverse\\TokenUniverse\./ nocase ascii wide
                        $string6 = "diversenok/TokenUniverse" nocase ascii wide
                        $string7 = /TokenUniverse\.dproj/ nocase ascii wide
                        $string8 = /TokenUniverse\.exe/ nocase ascii wide
                        $string9 = /TokenUniverse\-master\.zip/ nocase ascii wide
                        $string10 = /TokenUniverse\-x64\.zip/ nocase ascii wide
                        $string11 = /TokenUniverse\-x86\.zip/ nocase ascii wide

    condition:
        any of them
}