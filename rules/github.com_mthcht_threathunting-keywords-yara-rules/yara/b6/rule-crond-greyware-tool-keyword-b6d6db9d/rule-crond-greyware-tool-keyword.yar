rule rule_crond_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'crond' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "crond"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_crond_greyware_tool_keyword = /cp\s\-i\s\/bin\/sh\s.{0,1000}\/crond/

    condition:
        any of them
}