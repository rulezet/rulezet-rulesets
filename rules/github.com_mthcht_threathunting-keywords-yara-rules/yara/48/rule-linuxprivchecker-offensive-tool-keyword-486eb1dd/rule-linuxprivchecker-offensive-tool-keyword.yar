rule rule_linuxprivchecker_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'linuxprivchecker' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "linuxprivchecker"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_linuxprivchecker_offensive_tool_keyword = /\s\-name\s\.htpasswd/
                        $string2_linuxprivchecker_offensive_tool_keyword = " -perm -2000 -o -perm -4000"
                        $string3_linuxprivchecker_offensive_tool_keyword = /\/linuxprivchecker\.git/
                        $string4_linuxprivchecker_offensive_tool_keyword = "24d861124682031773ac0f6df9e5011b18a8d925c8c22469330826e64ccc2bab"
                        $string5_linuxprivchecker_offensive_tool_keyword = "cat /etc/shadow"
                        $string6_linuxprivchecker_offensive_tool_keyword = "cat /etc/sudoers 2>/dev/null"
                        $string7_linuxprivchecker_offensive_tool_keyword = /find\s\/\s\-exec\s\/usr\/bin\/awk\s\'BEGIN\s\{system\(\\\\"\/bin\/bash\\\\"/
                        $string8_linuxprivchecker_offensive_tool_keyword = /find.{0,1000}\s\-perm\s\-4000\s/
                        $string9_linuxprivchecker_offensive_tool_keyword = /http\:\/\/www\.exploit\-db\.com\/exploits\// nocase ascii wide
                        $string10_linuxprivchecker_offensive_tool_keyword = /linuxprivchecker\.py/
                        $string11_linuxprivchecker_offensive_tool_keyword = "sleventyeleven/linuxprivchecker"

    condition:
        any of them
}