rule wifite2
{
    meta:
        description = "Detection patterns for the tool 'wifite2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wifite2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/wifite -c " nocase ascii wide
                        $string2 = "/wifite2" nocase ascii wide
                        $string3 = "wifite --crack" nocase ascii wide
                        $string4 = "wifite -e " nocase ascii wide
                        $string5 = "wifite --wep " nocase ascii wide
                        $string6 = /Wifite\.py/ nocase ascii wide
                        $string7 = /wifite2\.git/ nocase ascii wide

    condition:
        any of them
}