rule rule_cracklord_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'cracklord' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cracklord"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_cracklord_offensive_tool_keyword = /\/cracklord\.git/ nocase ascii wide
                        $string2_cracklord_offensive_tool_keyword = "/cracklord/cmd/" nocase ascii wide
                        $string3_cracklord_offensive_tool_keyword = /cracklord\-master\./ nocase ascii wide
                        $string4_cracklord_offensive_tool_keyword = /cracklord\-queued.{0,1000}_amd64\.deb/ nocase ascii wide
                        $string5_cracklord_offensive_tool_keyword = /cracklord\-resourced.{0,1000}_amd64\.deb/ nocase ascii wide
                        $string6_cracklord_offensive_tool_keyword = "jmmcatee/cracklord" nocase ascii wide

    condition:
        any of them
}