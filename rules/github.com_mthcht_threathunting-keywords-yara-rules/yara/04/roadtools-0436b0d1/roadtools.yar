rule ROADtools
{
    meta:
        description = "Detection patterns for the tool 'ROADtools' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ROADtools"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sauth\s\-\-prt\s.{0,1000}\s\-\-prt\-sessionkey\s/ nocase ascii wide
                        $string2 = "/ROADtools/" nocase ascii wide
                        $string3 = /\\ROADtools\\/ nocase ascii wide
                        $string4 = "1e2136c0b4bef6f7a9de7cd1d57d2c5f3dae7f90116b50454db495970d0fe251" nocase ascii wide
                        $string5 = /dirkjan\@outsidersecurity\.nl/ nocase ascii wide
                        $string6 = /install\s.{0,1000}\sroadrecon/
                        $string7 = "pip install roadlib" nocase ascii wide
                        $string8 = "pip install roadrecon" nocase ascii wide
                        $string9 = "pip install roadtx" nocase ascii wide
                        $string10 = "roadrecon auth " nocase ascii wide
                        $string11 = "roadrecon dump " nocase ascii wide
                        $string12 = "roadrecon gather " nocase ascii wide
                        $string13 = "roadrecon plugin " nocase ascii wide
                        $string14 = /roadrecon.{0,1000}gather\.py/ nocase ascii wide
                        $string15 = /roadrecon\.db/ nocase ascii wide
                        $string16 = "roadrecon/frontend" nocase ascii wide
                        $string17 = /ROADtools\.git/ nocase ascii wide
                        $string18 = /roadtools\.roadlib\.auth/ nocase ascii wide
                        $string19 = /roadtools\.roadtx\.main\:main/ nocase ascii wide
                        $string20 = "ROADtools-master" nocase ascii wide
                        $string21 = "roadtx browserprtinject " nocase ascii wide
                        $string22 = "roadtx device -a delete " nocase ascii wide
                        $string23 = "roadtx getscope -s" nocase ascii wide
                        $string24 = "roadtx gettokens -u " nocase ascii wide
                        $string25 = "roadtx interactiveauth -c " nocase ascii wide
                        $string26 = "roadtx keepassauth -" nocase ascii wide
                        $string27 = /roadtx\sprt\s\-u\s.{0,1000}\-\-key\-pem\s/ nocase ascii wide
                        $string28 = "roadtx prtauth -" nocase ascii wide
                        $string29 = "roadtx refreshtokento -" nocase ascii wide

    condition:
        any of them
}