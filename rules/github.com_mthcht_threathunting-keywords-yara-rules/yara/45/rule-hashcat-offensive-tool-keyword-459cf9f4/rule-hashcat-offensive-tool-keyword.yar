rule rule_hashcat_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'hashcat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hashcat"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_hashcat_offensive_tool_keyword = /\s\-\-dc\-ip\s.{0,1000}\s\-request\s.{0,1000}\s\-format\shashcat/
                        $string2_hashcat_offensive_tool_keyword = /\sntlm\.wordlist\s.{0,1000}\-\-hex\-wordlist/
                        $string3_hashcat_offensive_tool_keyword = "hashcat"
                        $string4_hashcat_offensive_tool_keyword = /hashcat\-.{0,1000}\.7z/
                        $string5_hashcat_offensive_tool_keyword = /hashcat\.git/
                        $string6_hashcat_offensive_tool_keyword = "hashcat/hashcat"

    condition:
        any of them
}