rule SharpChrome
{
    meta:
        description = "Detection patterns for the tool 'SharpChrome' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpChrome"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/SharpChrome\.exe/ nocase ascii wide
                        $string2 = /\\SharpChrome\.exe/ nocase ascii wide
                        $string3 = /\\SharpChrome\.pdb/ nocase ascii wide
                        $string4 = ">SharpChrome<" nocase ascii wide
                        $string5 = "SharpChrome backupkey" nocase ascii wide

    condition:
        any of them
}