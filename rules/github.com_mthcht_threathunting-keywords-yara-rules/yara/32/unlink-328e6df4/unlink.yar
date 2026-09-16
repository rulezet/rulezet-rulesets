rule unlink
{
    meta:
        description = "Detection patterns for the tool 'unlink' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "unlink"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "unlink /var/log/"
                        $string2 = /unlink\s\~\/\.bash_history/ nocase ascii wide
                        $string3 = /unlink\s\~\/\.zsh_history/ nocase ascii wide
                        $string4 = "unlink -f /var/log/"
                        $string5 = "unlink -r /var/log/"
                        $string6 = "unlink -rf /var/log/"

    condition:
        any of them
}