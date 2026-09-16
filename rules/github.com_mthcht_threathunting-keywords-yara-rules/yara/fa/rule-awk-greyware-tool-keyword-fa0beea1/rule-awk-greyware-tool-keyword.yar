rule rule_awk_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'awk' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "awk"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_awk_greyware_tool_keyword = /sudo\sawk\s\'BEGIN\s\{system\(\\"\/bin\/bash\\"\)\}\'/

    condition:
        any of them
}