rule rule_mkdir_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'mkdir' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mkdir"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_mkdir_greyware_tool_keyword = /mkdir\s\~\/\.bash_history/

    condition:
        any of them
}