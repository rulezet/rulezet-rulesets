rule hashcat
{
    meta:
        description = "Detection patterns for the tool 'hashcat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hashcat"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-\-dc\-ip\s.{0,1000}\s\-request\s.{0,1000}\s\-format\shashcat/
                        $string2 = /\sntlm\.wordlist\s.{0,1000}\-\-hex\-wordlist/
                        $string3 = "hashcat"
                        $string4 = /hashcat\-.{0,1000}\.7z/
                        $string5 = /hashcat\.git/
                        $string6 = "hashcat/hashcat"

    condition:
        any of them
}