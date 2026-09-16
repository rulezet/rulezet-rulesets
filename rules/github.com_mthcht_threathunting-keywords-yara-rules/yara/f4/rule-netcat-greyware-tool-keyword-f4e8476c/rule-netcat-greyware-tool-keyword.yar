rule rule_netcat_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'netcat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "netcat"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_netcat_greyware_tool_keyword = /\/netcat\-win32\-.{0,1000}\.zip/
                        $string2_netcat_greyware_tool_keyword = /\\nc\.exe/ nocase ascii wide
                        $string3_netcat_greyware_tool_keyword = /\\netcat\-win32\-.{0,1000}\.zip/ nocase ascii wide
                        $string4_netcat_greyware_tool_keyword = /nc\s.{0,1000}\s\-e\s\/bin\/bash/
                        $string5_netcat_greyware_tool_keyword = "nc -u -lvp " nocase ascii wide
                        $string6_netcat_greyware_tool_keyword = /ncat\s.{0,1000}\s\-e\s\/bin\/bash/
                        $string7_netcat_greyware_tool_keyword = /ncat\s\-\-udp\s.{0,1000}\s\-e\s\/bin\/bash/
                        $string8_netcat_greyware_tool_keyword = /netcat\.exe/ nocase ascii wide

    condition:
        any of them
}