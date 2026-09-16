rule NoodleRAT
{
    meta:
        description = "Detection patterns for the tool 'NoodleRAT' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NoodleRAT"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/tmp\/\.llock/
                        $string2 = /\/usr\/include\/sdfwex\.h/
                        $string3 = /\\NoodMaker\.exe/ nocase ascii wide
                        $string4 = /NoodLinux\sv1\.0\.1/

    condition:
        any of them
}