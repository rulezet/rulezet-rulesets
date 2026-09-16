rule telnet
{
    meta:
        description = "Detection patterns for the tool 'telnet' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "telnet"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\&\&\stelnet\s.{0,1000}\s2\>\&1\s\<\/dev\/console/ nocase ascii wide
                        $string2 = /telnet\s.{0,1000}\s\|\s\/bin\/bash\s\|\stelnet\s/

    condition:
        any of them
}