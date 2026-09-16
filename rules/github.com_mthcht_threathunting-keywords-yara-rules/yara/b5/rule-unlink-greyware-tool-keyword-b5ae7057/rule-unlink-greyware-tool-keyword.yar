rule rule_unlink_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'unlink' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "unlink"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_unlink_greyware_tool_keyword = "unlink /var/log/"
                        $string2_unlink_greyware_tool_keyword = /unlink\s\~\/\.bash_history/ nocase ascii wide
                        $string3_unlink_greyware_tool_keyword = /unlink\s\~\/\.zsh_history/ nocase ascii wide
                        $string4_unlink_greyware_tool_keyword = "unlink -f /var/log/"
                        $string5_unlink_greyware_tool_keyword = "unlink -r /var/log/"
                        $string6_unlink_greyware_tool_keyword = "unlink -rf /var/log/"

    condition:
        any of them
}