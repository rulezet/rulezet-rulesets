rule Orc
{
    meta:
        description = "Detection patterns for the tool 'Orc' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Orc"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\smemexec\.pl/
                        $string2 = /\smemexec\.py/
                        $string3 = "#god bless you, NSA's autorootkit"
                        $string4 = /\/memexec\.pl/
                        $string5 = /\/memexec\.py/
                        $string6 = /\/suspect\/master\/suspect\.sh/
                        $string7 = "= Welcome to Orc Shell ="
                        $string8 = "50084b701b0463d1698211f2d0427c3eb6322be963c46cf9a4eb39e01a94cddc"
                        $string9 = "810b9f7c517f7f00516340661ecaf5610b89ea25ff5261964abe067a40c474c2"
                        $string10 = "find /tmp/ -executable -type f 2>/dev/null"
                        $string11 = "find /var/tmp -executable -type f 2>/dev/null"
                        $string12 = /getent\spasswd\s\|\sgrep\ssh\$\s\|\scut\s\-d\s/
                        $string13 = /linux\-exploit\-suggester\.sh/
                        $string14 = "lsattr -a /usr/bin/ /bin/ /sbin/ /usr/sbin/ 2>/dev/null"
                        $string15 = /orc_loadURL\s\'https\:\/\/gtfobins\.github\.io/
                        $string16 = "zMarch/Orc"

    condition:
        any of them
}