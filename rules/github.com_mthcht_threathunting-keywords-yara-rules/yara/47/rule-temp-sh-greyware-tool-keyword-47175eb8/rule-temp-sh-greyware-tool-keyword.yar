rule rule_temp_sh_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'temp.sh' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "temp.sh"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_temp_sh_greyware_tool_keyword = /http\:\/\/temp\.sh\/.{0,1000}\// nocase ascii wide
                        $string2_temp_sh_greyware_tool_keyword = /https\:\/\/temp\.sh\/.{0,1000}\// nocase ascii wide
                        $string3_temp_sh_greyware_tool_keyword = /https\:\/\/temp\.sh\/upload/ nocase ascii wide

    condition:
        any of them
}