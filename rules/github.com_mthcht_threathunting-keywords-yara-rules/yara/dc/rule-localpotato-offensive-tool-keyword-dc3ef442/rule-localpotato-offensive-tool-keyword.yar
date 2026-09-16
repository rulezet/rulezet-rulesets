rule rule_localpotato_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'localpotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "localpotato"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_localpotato_offensive_tool_keyword = /\s\/potato\.local/ nocase ascii wide
                        $string2_localpotato_offensive_tool_keyword = /\/evil\.dll/ nocase ascii wide
                        $string3_localpotato_offensive_tool_keyword = /\/LocalPotato\.git/ nocase ascii wide
                        $string4_localpotato_offensive_tool_keyword = /\/webdavshare\/potato\.local/ nocase ascii wide
                        $string5_localpotato_offensive_tool_keyword = /\[\!\]\sHTTP\sreflected\sDCOM\sauthentication\sfailed\s/ nocase ascii wide
                        $string6_localpotato_offensive_tool_keyword = /\[\!\]\sSMB\sreflected\sDCOM\sauthentication\sfailed/ nocase ascii wide
                        $string7_localpotato_offensive_tool_keyword = /\[\+\]\sHTTP\sClient\sAuth\sContext\sswapped\swith\sSYSTEM\s/ nocase ascii wide
                        $string8_localpotato_offensive_tool_keyword = /\[\+\]\sHTTP\sreflected\sDCOM\sauthentication\ssucceeded\!/ nocase ascii wide
                        $string9_localpotato_offensive_tool_keyword = /\[\+\]\sSMB\sreflected\sDCOM\sauthentication\ssucceeded\!/ nocase ascii wide
                        $string10_localpotato_offensive_tool_keyword = /\[\+\]\sSMB\sreflected\sDCOM\sauthentication\ssucceeded\!/ nocase ascii wide
                        $string11_localpotato_offensive_tool_keyword = /\\evil\.dll/ nocase ascii wide
                        $string12_localpotato_offensive_tool_keyword = /\\LocalPotato\\.{0,1000}\.cpp/ nocase ascii wide
                        $string13_localpotato_offensive_tool_keyword = /\\LocalPotato\\.{0,1000}\.exe/ nocase ascii wide
                        $string14_localpotato_offensive_tool_keyword = /\\PotatoTrigger\.cpp/ nocase ascii wide
                        $string15_localpotato_offensive_tool_keyword = /\]\sReceived\sDCOM\sNTLM\stype\s3\sauthentication\sfrom\sthe\sprivileged\sclient/ nocase ascii wide
                        $string16_localpotato_offensive_tool_keyword = "1B3C96A3-F698-472B-B786-6FED7A205159" nocase ascii wide
                        $string17_localpotato_offensive_tool_keyword = "-c 854A20FB-2D44-457D-992F-EF13785D2B51" nocase ascii wide
                        $string18_localpotato_offensive_tool_keyword = /DCOMReflection\.cpp/ nocase ascii wide
                        $string19_localpotato_offensive_tool_keyword = "decoder-it/LocalPotato" nocase ascii wide
                        $string20_localpotato_offensive_tool_keyword = /IUnknownObj\.cpp/ nocase ascii wide
                        $string21_localpotato_offensive_tool_keyword = /LocalPotato\s\(aka\sCVE\-2023\-21746\s\&\sHTTP\/WebDAV\)/ nocase ascii wide
                        $string22_localpotato_offensive_tool_keyword = "localpotato -i" nocase ascii wide
                        $string23_localpotato_offensive_tool_keyword = /LocalPotato\.cpp/ nocase ascii wide
                        $string24_localpotato_offensive_tool_keyword = /LocalPotato\.exe/ nocase ascii wide
                        $string25_localpotato_offensive_tool_keyword = /LocalPotato\.html/ nocase ascii wide
                        $string26_localpotato_offensive_tool_keyword = /LocalPotato\.sln/ nocase ascii wide
                        $string27_localpotato_offensive_tool_keyword = /LocalPotato\.vcxproj/ nocase ascii wide
                        $string28_localpotato_offensive_tool_keyword = /LocalPotato\.zip/ nocase ascii wide
                        $string29_localpotato_offensive_tool_keyword = "LocalPotato-master" nocase ascii wide

    condition:
        any of them
}