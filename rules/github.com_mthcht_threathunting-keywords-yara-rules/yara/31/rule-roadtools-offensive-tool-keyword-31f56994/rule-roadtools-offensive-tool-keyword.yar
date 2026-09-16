rule rule_ROADtools_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ROADtools' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ROADtools"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ROADtools_offensive_tool_keyword = /\sauth\s\-\-prt\s.{0,1000}\s\-\-prt\-sessionkey\s/ nocase ascii wide
                        $string2_ROADtools_offensive_tool_keyword = "/ROADtools/" nocase ascii wide
                        $string3_ROADtools_offensive_tool_keyword = /\\ROADtools\\/ nocase ascii wide
                        $string4_ROADtools_offensive_tool_keyword = "1e2136c0b4bef6f7a9de7cd1d57d2c5f3dae7f90116b50454db495970d0fe251" nocase ascii wide
                        $string5_ROADtools_offensive_tool_keyword = /dirkjan\@outsidersecurity\.nl/ nocase ascii wide
                        $string6_ROADtools_offensive_tool_keyword = /install\s.{0,1000}\sroadrecon/
                        $string7_ROADtools_offensive_tool_keyword = "pip install roadlib" nocase ascii wide
                        $string8_ROADtools_offensive_tool_keyword = "pip install roadrecon" nocase ascii wide
                        $string9_ROADtools_offensive_tool_keyword = "pip install roadtx" nocase ascii wide
                        $string10_ROADtools_offensive_tool_keyword = "roadrecon auth " nocase ascii wide
                        $string11_ROADtools_offensive_tool_keyword = "roadrecon dump " nocase ascii wide
                        $string12_ROADtools_offensive_tool_keyword = "roadrecon gather " nocase ascii wide
                        $string13_ROADtools_offensive_tool_keyword = "roadrecon plugin " nocase ascii wide
                        $string14_ROADtools_offensive_tool_keyword = /roadrecon.{0,1000}gather\.py/ nocase ascii wide
                        $string15_ROADtools_offensive_tool_keyword = /roadrecon\.db/ nocase ascii wide
                        $string16_ROADtools_offensive_tool_keyword = "roadrecon/frontend" nocase ascii wide
                        $string17_ROADtools_offensive_tool_keyword = /ROADtools\.git/ nocase ascii wide
                        $string18_ROADtools_offensive_tool_keyword = /roadtools\.roadlib\.auth/ nocase ascii wide
                        $string19_ROADtools_offensive_tool_keyword = /roadtools\.roadtx\.main\:main/ nocase ascii wide
                        $string20_ROADtools_offensive_tool_keyword = "ROADtools-master" nocase ascii wide
                        $string21_ROADtools_offensive_tool_keyword = "roadtx browserprtinject " nocase ascii wide
                        $string22_ROADtools_offensive_tool_keyword = "roadtx device -a delete " nocase ascii wide
                        $string23_ROADtools_offensive_tool_keyword = "roadtx getscope -s" nocase ascii wide
                        $string24_ROADtools_offensive_tool_keyword = "roadtx gettokens -u " nocase ascii wide
                        $string25_ROADtools_offensive_tool_keyword = "roadtx interactiveauth -c " nocase ascii wide
                        $string26_ROADtools_offensive_tool_keyword = "roadtx keepassauth -" nocase ascii wide
                        $string27_ROADtools_offensive_tool_keyword = /roadtx\sprt\s\-u\s.{0,1000}\-\-key\-pem\s/ nocase ascii wide
                        $string28_ROADtools_offensive_tool_keyword = "roadtx prtauth -" nocase ascii wide
                        $string29_ROADtools_offensive_tool_keyword = "roadtx refreshtokento -" nocase ascii wide

    condition:
        any of them
}