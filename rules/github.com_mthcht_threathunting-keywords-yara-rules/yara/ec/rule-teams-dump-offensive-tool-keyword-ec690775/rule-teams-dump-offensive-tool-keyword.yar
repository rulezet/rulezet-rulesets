rule rule_teams_dump_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'teams_dump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "teams_dump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_teams_dump_offensive_tool_keyword = /\steams_dump\.py/ nocase ascii wide
                        $string2_teams_dump_offensive_tool_keyword = /\steams_dump\.py/ nocase ascii wide
                        $string3_teams_dump_offensive_tool_keyword = /\.py\steams\s\-\-get/ nocase ascii wide
                        $string4_teams_dump_offensive_tool_keyword = /\.py\steams\s\-\-list/ nocase ascii wide
                        $string5_teams_dump_offensive_tool_keyword = /\/teams_cookies_output\.json/ nocase ascii wide
                        $string6_teams_dump_offensive_tool_keyword = /\/teams_dump\.git/ nocase ascii wide
                        $string7_teams_dump_offensive_tool_keyword = /\/teams_dump\.git/ nocase ascii wide
                        $string8_teams_dump_offensive_tool_keyword = /\/teams_dump\.py/ nocase ascii wide
                        $string9_teams_dump_offensive_tool_keyword = /\/teams_dump\.py/ nocase ascii wide
                        $string10_teams_dump_offensive_tool_keyword = /\\teams_dump\.py/ nocase ascii wide
                        $string11_teams_dump_offensive_tool_keyword = /\\teams_dump\.py/ nocase ascii wide
                        $string12_teams_dump_offensive_tool_keyword = "0a0f2a82d5f3dbd8d9f8c6031b2ebb8c1820cf370e6b4fae2b1396cf2107dddd" nocase ascii wide
                        $string13_teams_dump_offensive_tool_keyword = "1f17ea5b2d547497145f092cc3b7f0ed8acbb821946a5d3265423b7262f2aa4f" nocase ascii wide
                        $string14_teams_dump_offensive_tool_keyword = "bc11b2b14526fef7b745fa22f0359235fab202060716f0c9544e4ef899c7312e" nocase ascii wide
                        $string15_teams_dump_offensive_tool_keyword = "byinarie/teams_dump" nocase ascii wide
                        $string16_teams_dump_offensive_tool_keyword = "byinarie/teams_dump" nocase ascii wide
                        $string17_teams_dump_offensive_tool_keyword = /teams_dump\.py\steams/ nocase ascii wide
                        $string18_teams_dump_offensive_tool_keyword = /teams_dump\-main\.zip/ nocase ascii wide

    condition:
        any of them
}