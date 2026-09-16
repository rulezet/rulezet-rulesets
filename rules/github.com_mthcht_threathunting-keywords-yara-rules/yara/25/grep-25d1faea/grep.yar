rule grep
{
    meta:
        description = "Detection patterns for the tool 'grep' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "grep"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /grep\s\-.{0,1000}\s.{0,1000}DBPassword/
                        $string2 = /grep\s.{0,1000}password\s\/var\/www/
                        $string3 = /grep\s.{0,1000}password\..{0,1000}\s\/etc\/.{0,1000}\.conf/
                        $string4 = "grep :0: /etc/passwd"
                        $string5 = "grep -i pass "
                        $string6 = "grep -i user "
                        $string7 = "grep -R db_passwd"
                        $string8 = /grep\s\-roiE\s.{0,1000}password/
                        $string9 = /grep.{0,1000}\|pwd\=\|passwd\=\|password\=/
                        $string10 = /grep.{0,1000}password\|pwd\|pass/
                        $string11 = /strings\s\-n\s.{0,1000}\s\/dev\/mem\s\|\sgrep\s\-i\spass/

    condition:
        any of them
}