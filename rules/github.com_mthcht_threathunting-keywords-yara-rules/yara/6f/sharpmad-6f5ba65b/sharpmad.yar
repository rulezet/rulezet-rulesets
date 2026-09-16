rule Sharpmad
{
    meta:
        description = "Detection patterns for the tool 'Sharpmad' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Sharpmad"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/Sharpmad\.exe/ nocase ascii wide
                        $string2 = /\\Sharpmad\.exe/ nocase ascii wide
                        $string3 = /\\Sharpmad\.pdb/ nocase ascii wide
                        $string4 = ">Sharpmad<" nocase ascii wide

    condition:
        any of them
}