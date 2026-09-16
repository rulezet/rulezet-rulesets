rule rule_NoodleRAT_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'NoodleRAT' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NoodleRAT"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_NoodleRAT_offensive_tool_keyword = /\/tmp\/\.llock/
                        $string2_NoodleRAT_offensive_tool_keyword = /\/usr\/include\/sdfwex\.h/
                        $string3_NoodleRAT_offensive_tool_keyword = /\\NoodMaker\.exe/ nocase ascii wide
                        $string4_NoodleRAT_offensive_tool_keyword = /NoodLinux\sv1\.0\.1/

    condition:
        any of them
}