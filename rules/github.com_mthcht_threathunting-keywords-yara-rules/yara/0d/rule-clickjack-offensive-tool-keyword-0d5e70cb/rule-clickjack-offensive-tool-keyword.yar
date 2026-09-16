rule rule_clickjack_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'clickjack' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "clickjack"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_clickjack_offensive_tool_keyword = /\s\-\-CollectLinks\s\-\-apitoken\s.{0,1000}\s\-\-outfile\s/ nocase ascii wide
                        $string2_clickjack_offensive_tool_keyword = /\s\-\-Inject\s\-\-stub\s.{0,1000}\.dll.{0,1000}\s\-\-app\s/ nocase ascii wide
                        $string3_clickjack_offensive_tool_keyword = /\/ClickJack\.exe/ nocase ascii wide
                        $string4_clickjack_offensive_tool_keyword = /\[\!\]\sThis\sapplication\scan\snot\sbe\sinjected/ nocase ascii wide
                        $string5_clickjack_offensive_tool_keyword = /\[\+\]\sThis\sapplication\sis\sinjectable\!/ nocase ascii wide
                        $string6_clickjack_offensive_tool_keyword = /\\ClickJack\.csproj/ nocase ascii wide
                        $string7_clickjack_offensive_tool_keyword = /\\ClickJack\.exe/ nocase ascii wide
                        $string8_clickjack_offensive_tool_keyword = "02FAF312-BF2A-466B-8AD2-1339A31C303B" nocase ascii wide
                        $string9_clickjack_offensive_tool_keyword = "40e8b756d0f996d7127ffc76d3fb122dd014455bc6b0c007e6d5d77e5bb6211b" nocase ascii wide
                        $string10_clickjack_offensive_tool_keyword = "88f333f2f21ca05e44a91c376022997c2bbec79b9d9982d59ee6d38183df86f3" nocase ascii wide
                        $string11_clickjack_offensive_tool_keyword = /InjectApp\.InfectClickonceApp\(/ nocase ascii wide
                        $string12_clickjack_offensive_tool_keyword = /using\sClickJack\.Extensions/ nocase ascii wide
                        $string13_clickjack_offensive_tool_keyword = /using\sClickJack\.Modules/ nocase ascii wide

    condition:
        any of them
}