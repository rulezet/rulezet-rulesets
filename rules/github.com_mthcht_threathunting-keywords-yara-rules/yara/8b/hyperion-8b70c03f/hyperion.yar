rule hyperion
{
    meta:
        description = "Detection patterns for the tool 'hyperion' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hyperion"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/hyperion\.exe/ nocase ascii wide
                        $string2 = "/windows-resources/hyperion" nocase ascii wide
                        $string3 = /\\hyperion\.exe/ nocase ascii wide
                        $string4 = "apt install hyperion" nocase ascii wide
                        $string5 = "Hyperion PE-Crypter" nocase ascii wide
                        $string6 = /hyperion\.exe\s/ nocase ascii wide
                        $string7 = /hyperion_2\.0\.orig\.tar\.gz/ nocase ascii wide

    condition:
        any of them
}