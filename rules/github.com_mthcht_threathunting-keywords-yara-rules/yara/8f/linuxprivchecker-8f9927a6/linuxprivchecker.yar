rule linuxprivchecker
{
    meta:
        description = "Detection patterns for the tool 'linuxprivchecker' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "linuxprivchecker"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-name\s\.htpasswd/
                        $string2 = " -perm -2000 -o -perm -4000"
                        $string3 = /\/linuxprivchecker\.git/
                        $string4 = "24d861124682031773ac0f6df9e5011b18a8d925c8c22469330826e64ccc2bab"
                        $string5 = "cat /etc/shadow"
                        $string6 = "cat /etc/sudoers 2>/dev/null"
                        $string7 = /find\s\/\s\-exec\s\/usr\/bin\/awk\s\'BEGIN\s\{system\(\\\\"\/bin\/bash\\\\"/
                        $string8 = /find.{0,1000}\s\-perm\s\-4000\s/
                        $string9 = /http\:\/\/www\.exploit\-db\.com\/exploits\// nocase ascii wide
                        $string10 = /linuxprivchecker\.py/
                        $string11 = "sleventyeleven/linuxprivchecker"

    condition:
        any of them
}