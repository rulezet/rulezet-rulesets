rule rule_ncat_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ncat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ncat"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_ncat_greyware_tool_keyword = /\sncat\s.{0,1000}\s\-e\s\/bin\/bash.{0,1000}\|crontab/
                        $string2_ncat_greyware_tool_keyword = /ncat\s.{0,1000}\s\-p\s4444/

    condition:
        any of them
}