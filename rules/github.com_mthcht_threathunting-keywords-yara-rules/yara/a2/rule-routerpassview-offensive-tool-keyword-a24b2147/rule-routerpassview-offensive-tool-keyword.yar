rule rule_RouterPassView_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RouterPassView' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RouterPassView"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RouterPassView_offensive_tool_keyword = ">RouterPassView<" nocase ascii wide
                        $string2_RouterPassView_offensive_tool_keyword = "3ee00a42a65d2df9ee571875a11f53b56c8494e90e1e8e60e128aabdb56399c8" nocase ascii wide
                        $string3_RouterPassView_offensive_tool_keyword = "3ee00a42a65d2df9ee571875a11f53b56c8494e90e1e8e60e128aabdb56399c8" nocase ascii wide
                        $string4_RouterPassView_offensive_tool_keyword = "d3821591de381cb2861c5cf554009e51d7afe51b7c14e89b6f06a666bab949ff" nocase ascii wide
                        $string5_RouterPassView_offensive_tool_keyword = "Grab Password From IE Window" nocase ascii wide
                        $string6_RouterPassView_offensive_tool_keyword = /RouterPassView\.exe/ nocase ascii wide
                        $string7_RouterPassView_offensive_tool_keyword = /routerpassview\.zip/ nocase ascii wide

    condition:
        any of them
}