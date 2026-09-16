rule rule_spraycharles_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'spraycharles' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "spraycharles"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_spraycharles_offensive_tool_keyword = " install spraycharles" nocase ascii wide
                        $string2_spraycharles_offensive_tool_keyword = /\sspray\s\-u\s.{0,1000}\s\-H\s.{0,1000}\s\-p\s.{0,1000}\s\-m\sowa/ nocase ascii wide
                        $string3_spraycharles_offensive_tool_keyword = /\sspray\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-m\sOffice365/ nocase ascii wide
                        $string4_spraycharles_offensive_tool_keyword = /\sspray\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-m\sSmb\s\-H\s/ nocase ascii wide
                        $string5_spraycharles_offensive_tool_keyword = /\sspraycharles\.py/ nocase ascii wide
                        $string6_spraycharles_offensive_tool_keyword = /\/\.spraycharles\/logs/
                        $string7_spraycharles_offensive_tool_keyword = /\/\.spraycharles\/out/
                        $string8_spraycharles_offensive_tool_keyword = /\/\.spraycharles\:\/root\/\.spraycharles/
                        $string9_spraycharles_offensive_tool_keyword = /\/root\/\.local\/bin\/spraycharles/
                        $string10_spraycharles_offensive_tool_keyword = /\/spraycharles\.git/ nocase ascii wide
                        $string11_spraycharles_offensive_tool_keyword = /\/spraycharles\.py/ nocase ascii wide
                        $string12_spraycharles_offensive_tool_keyword = /\/tmp\/passwords\.txt/
                        $string13_spraycharles_offensive_tool_keyword = /\\spraycharles\.py/ nocase ascii wide
                        $string14_spraycharles_offensive_tool_keyword = "a89da438ecbe2e8c5f65e2bcbf5d82a84d26ba56dff46eb180c9de213f5a1871" nocase ascii wide
                        $string15_spraycharles_offensive_tool_keyword = /docker\sbuild\s\.\s\-t\sspraycharles/ nocase ascii wide
                        $string16_spraycharles_offensive_tool_keyword = "from spraycharles import " nocase ascii wide
                        $string17_spraycharles_offensive_tool_keyword = "spraycharles analyze " nocase ascii wide
                        $string18_spraycharles_offensive_tool_keyword = "spraycharles gen extras" nocase ascii wide
                        $string19_spraycharles_offensive_tool_keyword = "spraycharles spray" nocase ascii wide
                        $string20_spraycharles_offensive_tool_keyword = "Tw1sm/spraycharles" nocase ascii wide

    condition:
        any of them
}