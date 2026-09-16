rule rule_rm_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'rm' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rm"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_rm_greyware_tool_keyword = /rm\s\$HISTFILE/ nocase ascii wide
                        $string2_rm_greyware_tool_keyword = /rm\s\.bash_history/
                        $string3_rm_greyware_tool_keyword = "rm /var/log/"
                        $string4_rm_greyware_tool_keyword = /rm\s\/var\/log\/.{0,1000}\.log/
                        $string5_rm_greyware_tool_keyword = /rm\s\~\/\.bash_history/
                        $string6_rm_greyware_tool_keyword = /rm\s\-f\s.{0,1000}\.bash_history/ nocase ascii wide
                        $string7_rm_greyware_tool_keyword = /rm\s\-f\s.{0,1000}\.zsh_history/ nocase ascii wide
                        $string8_rm_greyware_tool_keyword = "rm -f /var/log/"
                        $string9_rm_greyware_tool_keyword = /rm\s\-fr\s.{0,1000}\.zsh_history/ nocase ascii wide
                        $string10_rm_greyware_tool_keyword = "rm -r /var/log/"
                        $string11_rm_greyware_tool_keyword = /rm\s\-rf\s.{0,1000}\.zsh_history/ nocase ascii wide
                        $string12_rm_greyware_tool_keyword = /rm\s\-rf\s\.bash_history/
                        $string13_rm_greyware_tool_keyword = "rm -rf /var/log/"
                        $string14_rm_greyware_tool_keyword = "rm -rf /var/log/messages"
                        $string15_rm_greyware_tool_keyword = "rm -rf /var/log/security"
                        $string16_rm_greyware_tool_keyword = /rm\s\-rf\s\~\/\.bash_history/

    condition:
        any of them
}