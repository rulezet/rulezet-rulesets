rule ncat
{
    meta:
        description = "Detection patterns for the tool 'ncat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ncat"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\sncat\s.{0,1000}\s\-e\s\/bin\/bash.{0,1000}\|crontab/
                        $string2 = /ncat\s.{0,1000}\s\-p\s4444/

    condition:
        any of them
}