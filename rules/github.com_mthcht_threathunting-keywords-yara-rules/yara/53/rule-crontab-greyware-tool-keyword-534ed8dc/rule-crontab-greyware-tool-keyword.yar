rule rule_crontab_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'crontab' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "crontab"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_crontab_greyware_tool_keyword = /crontab.{0,1000}\ssleep\s.{0,1000}ncat\s.{0,1000}\s\-e\s\/bin\/bash.{0,1000}crontab/

    condition:
        any of them
}