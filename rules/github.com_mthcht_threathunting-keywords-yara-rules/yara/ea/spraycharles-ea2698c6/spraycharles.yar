rule spraycharles
{
    meta:
        description = "Detection patterns for the tool 'spraycharles' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "spraycharles"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " install spraycharles" nocase ascii wide
                        $string2 = /\sspray\s\-u\s.{0,1000}\s\-H\s.{0,1000}\s\-p\s.{0,1000}\s\-m\sowa/ nocase ascii wide
                        $string3 = /\sspray\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-m\sOffice365/ nocase ascii wide
                        $string4 = /\sspray\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-m\sSmb\s\-H\s/ nocase ascii wide
                        $string5 = /\sspraycharles\.py/ nocase ascii wide
                        $string6 = /\/\.spraycharles\/logs/
                        $string7 = /\/\.spraycharles\/out/
                        $string8 = /\/\.spraycharles\:\/root\/\.spraycharles/
                        $string9 = /\/root\/\.local\/bin\/spraycharles/
                        $string10 = /\/spraycharles\.git/ nocase ascii wide
                        $string11 = /\/spraycharles\.py/ nocase ascii wide
                        $string12 = /\/tmp\/passwords\.txt/
                        $string13 = /\\spraycharles\.py/ nocase ascii wide
                        $string14 = "a89da438ecbe2e8c5f65e2bcbf5d82a84d26ba56dff46eb180c9de213f5a1871" nocase ascii wide
                        $string15 = /docker\sbuild\s\.\s\-t\sspraycharles/ nocase ascii wide
                        $string16 = "from spraycharles import " nocase ascii wide
                        $string17 = "spraycharles analyze " nocase ascii wide
                        $string18 = "spraycharles gen extras" nocase ascii wide
                        $string19 = "spraycharles spray" nocase ascii wide
                        $string20 = "Tw1sm/spraycharles" nocase ascii wide

    condition:
        any of them
}