rule impacket
{
    meta:
        description = "Detection patterns for the tool 'impacket' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "impacket"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /cmd\.exe\s\/Q\s\/c\sdir\s1\>\s.{0,1000}\s2\>\&1\s\&\&\scertutil\s\-encodehex\s/ nocase ascii wide
                        $string2 = /cmd\.exe\s\/Q\s\/c\shostname\s1\>\s.{0,1000}\s2\>\&1\s\&\&\scertutil\s\-encodehex\s/ nocase ascii wide
                        $string3 = /cmd\.exe\s\/Q\s\/c\shostname\s1\>\s.{0,1000}\s2\>\&1\s\&\&\scertutil\s\-encodehex\s/ nocase ascii wide
                        $string4 = /cmd\.exe\s\/Q\s\/c\sipconfig\s1\>\s.{0,1000}\s2\>\&1\s\&\&\scertutil\s\-encodehex\s/ nocase ascii wide
                        $string5 = /cmd\.exe\s\/Q\s\/c\sipconfig\s1\>\s\\Windows\\Temp\\.{0,1000}\s2\>\&1/ nocase ascii wide

    condition:
        any of them
}