rule SilentHound
{
    meta:
        description = "Detection patterns for the tool 'SilentHound' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SilentHound"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " -k --kerberoast" nocase ascii wide
                        $string2 = /\/SilentHound\.git/ nocase ascii wide
                        $string3 = /\-domain_admins\.txt/ nocase ascii wide
                        $string4 = "layer8secure/SilentHound" nocase ascii wide
                        $string5 = "Nick Swink aka c0rnbread" nocase ascii wide
                        $string6 = /silenthound\.py/ nocase ascii wide
                        $string7 = "SilentHound-main" nocase ascii wide

    condition:
        any of them
}