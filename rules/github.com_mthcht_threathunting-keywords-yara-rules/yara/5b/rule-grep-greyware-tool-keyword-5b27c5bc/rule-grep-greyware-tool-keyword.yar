rule rule_grep_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'grep' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "grep"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_grep_greyware_tool_keyword = /grep\s\-.{0,1000}\s.{0,1000}DBPassword/
                        $string2_grep_greyware_tool_keyword = /grep\s.{0,1000}password\s\/var\/www/
                        $string3_grep_greyware_tool_keyword = /grep\s.{0,1000}password\..{0,1000}\s\/etc\/.{0,1000}\.conf/
                        $string4_grep_greyware_tool_keyword = "grep :0: /etc/passwd"
                        $string5_grep_greyware_tool_keyword = "grep -i pass "
                        $string6_grep_greyware_tool_keyword = "grep -i user "
                        $string7_grep_greyware_tool_keyword = "grep -R db_passwd"
                        $string8_grep_greyware_tool_keyword = /grep\s\-roiE\s.{0,1000}password/
                        $string9_grep_greyware_tool_keyword = /grep.{0,1000}\|pwd\=\|passwd\=\|password\=/
                        $string10_grep_greyware_tool_keyword = /grep.{0,1000}password\|pwd\|pass/
                        $string11_grep_greyware_tool_keyword = /strings\s\-n\s.{0,1000}\s\/dev\/mem\s\|\sgrep\s\-i\spass/

    condition:
        any of them
}