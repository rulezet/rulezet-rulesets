rule rm
{
    meta:
        description = "Detection patterns for the tool 'rm' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rm"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /rm\s\$HISTFILE/ nocase ascii wide
                        $string2 = /rm\s\.bash_history/
                        $string3 = "rm /var/log/"
                        $string4 = /rm\s\/var\/log\/.{0,1000}\.log/
                        $string5 = /rm\s\~\/\.bash_history/
                        $string6 = /rm\s\-f\s.{0,1000}\.bash_history/ nocase ascii wide
                        $string7 = /rm\s\-f\s.{0,1000}\.zsh_history/ nocase ascii wide
                        $string8 = "rm -f /var/log/"
                        $string9 = /rm\s\-fr\s.{0,1000}\.zsh_history/ nocase ascii wide
                        $string10 = "rm -r /var/log/"
                        $string11 = /rm\s\-rf\s.{0,1000}\.zsh_history/ nocase ascii wide
                        $string12 = /rm\s\-rf\s\.bash_history/
                        $string13 = "rm -rf /var/log/"
                        $string14 = "rm -rf /var/log/messages"
                        $string15 = "rm -rf /var/log/security"
                        $string16 = /rm\s\-rf\s\~\/\.bash_history/

    condition:
        any of them
}