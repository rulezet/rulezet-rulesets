rule rule_hashview_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'hashview' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hashview"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_hashview_offensive_tool_keyword = /\shashview\.py/ nocase ascii wide
                        $string2_hashview_offensive_tool_keyword = " hashview-agent " nocase ascii wide
                        $string3_hashview_offensive_tool_keyword = /\.\/hashview\//
                        $string4_hashview_offensive_tool_keyword = /\/hashview\.py/ nocase ascii wide
                        $string5_hashview_offensive_tool_keyword = /\\hashview\.py/ nocase ascii wide
                        $string6_hashview_offensive_tool_keyword = "DoNotUseThisPassword123!" nocase ascii wide
                        $string7_hashview_offensive_tool_keyword = /hashview.{0,1000}\@.{0,1000}localhost/ nocase ascii wide
                        $string8_hashview_offensive_tool_keyword = /hashview\/config\.conf/ nocase ascii wide
                        $string9_hashview_offensive_tool_keyword = "hashview/hashview" nocase ascii wide
                        $string10_hashview_offensive_tool_keyword = /hashview\-agent\..{0,1000}\.tgz/ nocase ascii wide
                        $string11_hashview_offensive_tool_keyword = /hashview\-agent\.py/ nocase ascii wide
                        $string12_hashview_offensive_tool_keyword = /rockyou\.txt\.gz/ nocase ascii wide
                        $string13_hashview_offensive_tool_keyword = /wordlists\/dynamic\-all\.txt/ nocase ascii wide
                        $string14_hashview_offensive_tool_keyword = /wordlists\/rockyou\.txt\'/ nocase ascii wide

    condition:
        any of them
}