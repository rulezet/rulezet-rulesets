rule rule_go_secdump_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'go-secdump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "go-secdump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_go_secdump_offensive_tool_keyword = /\.\/go\-secdump/
                        $string2_go_secdump_offensive_tool_keyword = /\/go\-secdump\.git/ nocase ascii wide
                        $string3_go_secdump_offensive_tool_keyword = /\\go\-secdump/ nocase ascii wide
                        $string4_go_secdump_offensive_tool_keyword = "go-secdump -" nocase ascii wide
                        $string5_go_secdump_offensive_tool_keyword = /go\-secdump\.exe/ nocase ascii wide
                        $string6_go_secdump_offensive_tool_keyword = "go-secdump-main" nocase ascii wide
                        $string7_go_secdump_offensive_tool_keyword = "jfjallid/go-secdump" nocase ascii wide

    condition:
        any of them
}