rule netcat
{
    meta:
        description = "Detection patterns for the tool 'netcat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "netcat"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/netcat\-win32\-.{0,1000}\.zip/
                        $string2 = /\\nc\.exe/ nocase ascii wide
                        $string3 = /\\netcat\-win32\-.{0,1000}\.zip/ nocase ascii wide
                        $string4 = /nc\s.{0,1000}\s\-e\s\/bin\/bash/
                        $string5 = "nc -u -lvp " nocase ascii wide
                        $string6 = /ncat\s.{0,1000}\s\-e\s\/bin\/bash/
                        $string7 = /ncat\s\-\-udp\s.{0,1000}\s\-e\s\/bin\/bash/
                        $string8 = /netcat\.exe/ nocase ascii wide

    condition:
        any of them
}