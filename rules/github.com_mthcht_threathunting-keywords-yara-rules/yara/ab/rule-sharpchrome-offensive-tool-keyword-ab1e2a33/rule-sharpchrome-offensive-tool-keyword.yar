rule rule_SharpChrome_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpChrome' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpChrome"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpChrome_offensive_tool_keyword = /\/SharpChrome\.exe/ nocase ascii wide
                        $string2_SharpChrome_offensive_tool_keyword = /\\SharpChrome\.exe/ nocase ascii wide
                        $string3_SharpChrome_offensive_tool_keyword = /\\SharpChrome\.pdb/ nocase ascii wide
                        $string4_SharpChrome_offensive_tool_keyword = ">SharpChrome<" nocase ascii wide
                        $string5_SharpChrome_offensive_tool_keyword = "SharpChrome backupkey" nocase ascii wide

    condition:
        any of them
}