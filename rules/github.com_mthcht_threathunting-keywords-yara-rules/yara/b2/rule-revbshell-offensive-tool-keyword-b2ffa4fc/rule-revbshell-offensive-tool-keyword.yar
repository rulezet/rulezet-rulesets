rule rule_revbshell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'revbshell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "revbshell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_revbshell_offensive_tool_keyword = /\/revbshell\.git/ nocase ascii wide
                        $string2_revbshell_offensive_tool_keyword = /\\revbshell\-master/ nocase ascii wide
                        $string3_revbshell_offensive_tool_keyword = "5f01ca453b976669370a3d5975837773107dd5522e8259dccda788993bb0da89" nocase ascii wide
                        $string4_revbshell_offensive_tool_keyword = "bitsadmin/revbshell" nocase ascii wide
                        $string5_revbshell_offensive_tool_keyword = "dcd8b443ee740b4ccd6674dd1e6b6cfccd9a202c282a67e06ce2f4aaa8a66d95" nocase ascii wide
                        $string6_revbshell_offensive_tool_keyword = /pentest\-script\-master\.zip/ nocase ascii wide

    condition:
        any of them
}