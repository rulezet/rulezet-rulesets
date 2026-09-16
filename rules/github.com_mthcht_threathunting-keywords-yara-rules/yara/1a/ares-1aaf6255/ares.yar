rule Ares
{
    meta:
        description = "Detection patterns for the tool 'Ares' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Ares"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s0\.0\.0\.0\:8080\s\-\-threads/ nocase ascii wide
                        $string2 = " http://localhost:8080 -o agent" nocase ascii wide
                        $string3 = /\/Ares\.git/ nocase ascii wide
                        $string4 = /\/ares\.py\s/ nocase ascii wide
                        $string5 = /ares\.py\srunserver/ nocase ascii wide
                        $string6 = /ares\-master\.zip/ nocase ascii wide
                        $string7 = /autostart\/ares\.desktop/ nocase ascii wide
                        $string8 = "gunicorn ares:app" nocase ascii wide
                        $string9 = /sqlite\:\/\/\/ares\.db/ nocase ascii wide
                        $string10 = "sweetsoftware/Ares" nocase ascii wide

    condition:
        any of them
}