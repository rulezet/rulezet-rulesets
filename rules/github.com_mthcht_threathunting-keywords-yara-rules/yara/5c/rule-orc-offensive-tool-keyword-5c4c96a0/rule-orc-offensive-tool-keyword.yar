rule rule_Orc_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Orc' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Orc"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Orc_offensive_tool_keyword = /\smemexec\.pl/
                        $string2_Orc_offensive_tool_keyword = /\smemexec\.py/
                        $string3_Orc_offensive_tool_keyword = "#god bless you, NSA's autorootkit"
                        $string4_Orc_offensive_tool_keyword = /\/memexec\.pl/
                        $string5_Orc_offensive_tool_keyword = /\/memexec\.py/
                        $string6_Orc_offensive_tool_keyword = /\/suspect\/master\/suspect\.sh/
                        $string7_Orc_offensive_tool_keyword = "= Welcome to Orc Shell ="
                        $string8_Orc_offensive_tool_keyword = "50084b701b0463d1698211f2d0427c3eb6322be963c46cf9a4eb39e01a94cddc"
                        $string9_Orc_offensive_tool_keyword = "810b9f7c517f7f00516340661ecaf5610b89ea25ff5261964abe067a40c474c2"
                        $string10_Orc_offensive_tool_keyword = "find /tmp/ -executable -type f 2>/dev/null"
                        $string11_Orc_offensive_tool_keyword = "find /var/tmp -executable -type f 2>/dev/null"
                        $string12_Orc_offensive_tool_keyword = /getent\spasswd\s\|\sgrep\ssh\$\s\|\scut\s\-d\s/
                        $string13_Orc_offensive_tool_keyword = /linux\-exploit\-suggester\.sh/
                        $string14_Orc_offensive_tool_keyword = "lsattr -a /usr/bin/ /bin/ /sbin/ /usr/sbin/ 2>/dev/null"
                        $string15_Orc_offensive_tool_keyword = /orc_loadURL\s\'https\:\/\/gtfobins\.github\.io/
                        $string16_Orc_offensive_tool_keyword = "zMarch/Orc"

    condition:
        any of them
}