rule rule_bash_keylogger_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'bash keylogger' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bash keylogger"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_bash_keylogger_greyware_tool_keyword = /history\s\-a.{0,1000}\stail\s\-n1\s\~\/\.bash_history\s\>\s\/dev\/tcp\/.{0,1000}\//

    condition:
        any of them
}