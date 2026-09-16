rule rule_GraphStrike_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'GraphStrike' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GraphStrike"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_GraphStrike_offensive_tool_keyword = /\sGraphStrike\.py/ nocase ascii wide
                        $string2_GraphStrike_offensive_tool_keyword = /\.cobaltstrike\.beacon_keys/ nocase ascii wide
                        $string3_GraphStrike_offensive_tool_keyword = /\/GraphStrike\.cna/ nocase ascii wide
                        $string4_GraphStrike_offensive_tool_keyword = /\/GraphStrike\.git/ nocase ascii wide
                        $string5_GraphStrike_offensive_tool_keyword = /\/graphstrike\.profile/ nocase ascii wide
                        $string6_GraphStrike_offensive_tool_keyword = /\/GraphStrike\.py/ nocase ascii wide
                        $string7_GraphStrike_offensive_tool_keyword = "/GraphStrike-main/" nocase ascii wide
                        $string8_GraphStrike_offensive_tool_keyword = "/opt/cobaltstrike/"
                        $string9_GraphStrike_offensive_tool_keyword = /\[\+\]\sRandomizing\ssyscall\snames/ nocase ascii wide
                        $string10_GraphStrike_offensive_tool_keyword = /\[\+\]\sUsing\sdomain\senumeration\sfor\ssandbox\sevasion/ nocase ascii wide
                        $string11_GraphStrike_offensive_tool_keyword = /\\GraphLdr\.x64\.bin/ nocase ascii wide
                        $string12_GraphStrike_offensive_tool_keyword = /\\GraphStrike\.cna/ nocase ascii wide
                        $string13_GraphStrike_offensive_tool_keyword = /\\GraphStrike\.py/ nocase ascii wide
                        $string14_GraphStrike_offensive_tool_keyword = /\\GraphStrike\-main\\/ nocase ascii wide
                        $string15_GraphStrike_offensive_tool_keyword = /change_sandbox_evasion_method\(/ nocase ascii wide
                        $string16_GraphStrike_offensive_tool_keyword = /GraphLdr\.x64\.bin/ nocase ascii wide
                        $string17_GraphStrike_offensive_tool_keyword = /GraphLdr\.x64\.exe/ nocase ascii wide
                        $string18_GraphStrike_offensive_tool_keyword = "GraphStrike Server is running and checking SharePoint for Beacon traffic" nocase ascii wide
                        $string19_GraphStrike_offensive_tool_keyword = /GraphStrike\.py\s/ nocase ascii wide
                        $string20_GraphStrike_offensive_tool_keyword = /Lost\sconnection\sto\steam\sserver\!\sSleeping\s60\ssecond\sand\sretrying\?/ nocase ascii wide
                        $string21_GraphStrike_offensive_tool_keyword = /Mozilla\/6\.0\s\(Windows\sNT\s10\.0\;\sWin64\;\sx64\)\sAppleWebKit\/537\.36\s\(KHTML\,\slike\sGecko\)\sChrome\/103\.0\.0\.0\sSafari\/537\.36/ nocase ascii wide
                        $string22_GraphStrike_offensive_tool_keyword = "RedSiege/GraphStrike" nocase ascii wide

    condition:
        any of them
}