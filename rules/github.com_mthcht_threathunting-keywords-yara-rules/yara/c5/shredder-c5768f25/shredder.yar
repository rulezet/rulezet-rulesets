rule Shredder
{
    meta:
        description = "Detection patterns for the tool 'Shredder' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Shredder"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\\file_shredder_setup\.tmp/ nocase ascii wide
                        $string2 = /\\Shredder\.exe/ nocase ascii wide
                        $string3 = ">File Shredder by PowTools<" nocase ascii wide
                        $string4 = /File\sShredder\ssetup\.exe/ nocase ascii wide
                        $string5 = /File\sShredder\.exe/ nocase ascii wide
                        $string6 = /file_shredder_setup\.exe/ nocase ascii wide
                        $string7 = /Program\sFiles\\File\sShredder\\/ nocase ascii wide

    condition:
        any of them
}