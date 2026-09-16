rule teams_dump
{
    meta:
        description = "Detection patterns for the tool 'teams_dump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "teams_dump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\steams_dump\.py/ nocase ascii wide
                        $string2 = /\steams_dump\.py/ nocase ascii wide
                        $string3 = /\.py\steams\s\-\-get/ nocase ascii wide
                        $string4 = /\.py\steams\s\-\-list/ nocase ascii wide
                        $string5 = /\/teams_cookies_output\.json/ nocase ascii wide
                        $string6 = /\/teams_dump\.git/ nocase ascii wide
                        $string7 = /\/teams_dump\.git/ nocase ascii wide
                        $string8 = /\/teams_dump\.py/ nocase ascii wide
                        $string9 = /\/teams_dump\.py/ nocase ascii wide
                        $string10 = /\\teams_dump\.py/ nocase ascii wide
                        $string11 = /\\teams_dump\.py/ nocase ascii wide
                        $string12 = "0a0f2a82d5f3dbd8d9f8c6031b2ebb8c1820cf370e6b4fae2b1396cf2107dddd" nocase ascii wide
                        $string13 = "1f17ea5b2d547497145f092cc3b7f0ed8acbb821946a5d3265423b7262f2aa4f" nocase ascii wide
                        $string14 = "bc11b2b14526fef7b745fa22f0359235fab202060716f0c9544e4ef899c7312e" nocase ascii wide
                        $string15 = "byinarie/teams_dump" nocase ascii wide
                        $string16 = "byinarie/teams_dump" nocase ascii wide
                        $string17 = /teams_dump\.py\steams/ nocase ascii wide
                        $string18 = /teams_dump\-main\.zip/ nocase ascii wide

    condition:
        any of them
}