rule BlockOpenHandle
{
    meta:
        description = "Detection patterns for the tool 'BlockOpenHandle' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BlockOpenHandle"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/BlockOpenHandle\.git/ nocase ascii wide
                        $string2 = "55F0368B-63DA-40E7-A8A5-289F70DF9C7F" nocase ascii wide
                        $string3 = /BlockOpenHandle\.cpp/ nocase ascii wide
                        $string4 = /BlockOpenHandle\.exe/ nocase ascii wide
                        $string5 = /BlockOpenHandle\.vcxproj/ nocase ascii wide
                        $string6 = "BlockOpenHandle-main" nocase ascii wide

    condition:
        any of them
}