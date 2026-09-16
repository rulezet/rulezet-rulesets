rule BrowsingHistoryView
{
    meta:
        description = "Detection patterns for the tool 'BrowsingHistoryView' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BrowsingHistoryView"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.exe\s\s\/HistorySource\s1\s\/SaveDirect\s\/scomma\s/ nocase ascii wide
                        $string2 = /\.exe\s\/HistorySource\s1\s\/LoadChrome\s1\s\/shtml\s/ nocase ascii wide
                        $string3 = ">BrowsingHistoryView<" nocase ascii wide
                        $string4 = "19a43d7ebc516f2344e6ffac66205d54cbde907e2eb1fb6171934d292524c5c7" nocase ascii wide
                        $string5 = "1cc45acf429d705ee592af1c9e56ac25f5b5acbc27fe555db5007c8be9cc4c42" nocase ascii wide
                        $string6 = "9f65528998b39f2e7239f89a56ded47ea865eea2d6b82b300cd5de7e62072cf0" nocase ascii wide
                        $string7 = /BrowsingHistoryView\.cfg/ nocase ascii wide
                        $string8 = /BrowsingHistoryView\.exe/ nocase ascii wide
                        $string9 = /BROWSINGHISTORYVIEW\.EXE\-.{0,1000}\.pf/ nocase ascii wide
                        $string10 = /browsinghistoryview\.zip/ nocase ascii wide
                        $string11 = /browsinghistoryview\-x64\.zip/ nocase ascii wide
                        $string12 = "c5bcfd00d0b8fda7c4b20cdc9649713d9f01dd12f61ce8ee9c45ec424a6bbdf2" nocase ascii wide
                        $string13 = /nirsoft\.net\/utils\/browsing_history_view\.html/ nocase ascii wide

    condition:
        any of them
}