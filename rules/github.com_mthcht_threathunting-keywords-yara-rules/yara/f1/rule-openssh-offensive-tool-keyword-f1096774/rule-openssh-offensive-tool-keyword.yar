rule rule_Openssh_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Openssh' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Openssh"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Openssh_offensive_tool_keyword = /\&\&\scat\s\/etc\/motd.{0,1000}exec\s\-a\s\-\$\(basename\s\$SHELL\)\s\$SHELL/
                        $string2_Openssh_offensive_tool_keyword = "5b5b20242873746174202d632559202f62696e2f73682920213d20242873746174202d632559202e73736829205d5d202626207b203a3b746f756368202d72202f62696e2f7368202e7373683b6578706f7274204b45593d22223b62617368202d63202224286375726c202d6673534c207468632e6f72672f737368782922" nocase ascii wide
                        $string3_Openssh_offensive_tool_keyword = "6563686f2048656c6c6f204261636b646f6f72" nocase ascii wide
                        $string4_Openssh_offensive_tool_keyword = /command\=.{0,1000}\#\#\#\-\-\-POWERSHELL\-\-\-.{0,1000}eval\s\$\(echo\s/ nocase ascii wide

    condition:
        any of them
}