rule temp_sh
{
    meta:
        description = "Detection patterns for the tool 'temp.sh' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "temp.sh"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /http\:\/\/temp\.sh\/.{0,1000}\// nocase ascii wide
                        $string2 = /https\:\/\/temp\.sh\/.{0,1000}\// nocase ascii wide
                        $string3 = /https\:\/\/temp\.sh\/upload/ nocase ascii wide

    condition:
        any of them
}