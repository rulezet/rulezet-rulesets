rule ren
{
    meta:
        description = "Detection patterns for the tool 'ren' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ren"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /ren\sC\:\\Windows\\System32\\amsi\.dll\s.{0,1000}\.dll/ nocase ascii wide
                        $string2 = /ren\ssethc\.exe\ssethcbad\.exe/ nocase ascii wide
                        $string3 = /ren\ssethcold\.exe\ssethc\.exe/ nocase ascii wide
                        $string4 = /ren\ssethcold\.exe\ssethc\.exe/ nocase ascii wide
                        $string5 = /ren\sSophosED\.sys\sSophosED\.sys\.old/ nocase ascii wide

    condition:
        any of them
}