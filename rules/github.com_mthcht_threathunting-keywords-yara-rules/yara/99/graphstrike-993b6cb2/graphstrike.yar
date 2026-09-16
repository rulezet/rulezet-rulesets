rule GraphStrike
{
    meta:
        description = "Detection patterns for the tool 'GraphStrike' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GraphStrike"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sGraphStrike\.py/ nocase ascii wide
                        $string2 = /\.cobaltstrike\.beacon_keys/ nocase ascii wide
                        $string3 = /\/GraphStrike\.cna/ nocase ascii wide
                        $string4 = /\/GraphStrike\.git/ nocase ascii wide
                        $string5 = /\/graphstrike\.profile/ nocase ascii wide
                        $string6 = /\/GraphStrike\.py/ nocase ascii wide
                        $string7 = "/GraphStrike-main/" nocase ascii wide
                        $string8 = "/opt/cobaltstrike/"
                        $string9 = /\[\+\]\sRandomizing\ssyscall\snames/ nocase ascii wide
                        $string10 = /\[\+\]\sUsing\sdomain\senumeration\sfor\ssandbox\sevasion/ nocase ascii wide
                        $string11 = /\\GraphLdr\.x64\.bin/ nocase ascii wide
                        $string12 = /\\GraphStrike\.cna/ nocase ascii wide
                        $string13 = /\\GraphStrike\.py/ nocase ascii wide
                        $string14 = /\\GraphStrike\-main\\/ nocase ascii wide
                        $string15 = /change_sandbox_evasion_method\(/ nocase ascii wide
                        $string16 = /GraphLdr\.x64\.bin/ nocase ascii wide
                        $string17 = /GraphLdr\.x64\.exe/ nocase ascii wide
                        $string18 = "GraphStrike Server is running and checking SharePoint for Beacon traffic" nocase ascii wide
                        $string19 = /GraphStrike\.py\s/ nocase ascii wide
                        $string20 = /Lost\sconnection\sto\steam\sserver\!\sSleeping\s60\ssecond\sand\sretrying\?/ nocase ascii wide
                        $string21 = /Mozilla\/6\.0\s\(Windows\sNT\s10\.0\;\sWin64\;\sx64\)\sAppleWebKit\/537\.36\s\(KHTML\,\slike\sGecko\)\sChrome\/103\.0\.0\.0\sSafari\/537\.36/ nocase ascii wide
                        $string22 = "RedSiege/GraphStrike" nocase ascii wide

    condition:
        any of them
}