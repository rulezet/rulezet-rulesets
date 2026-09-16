rule localpotato
{
    meta:
        description = "Detection patterns for the tool 'localpotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "localpotato"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\/potato\.local/ nocase ascii wide
                        $string2 = /\/evil\.dll/ nocase ascii wide
                        $string3 = /\/LocalPotato\.git/ nocase ascii wide
                        $string4 = /\/webdavshare\/potato\.local/ nocase ascii wide
                        $string5 = /\[\!\]\sHTTP\sreflected\sDCOM\sauthentication\sfailed\s/ nocase ascii wide
                        $string6 = /\[\!\]\sSMB\sreflected\sDCOM\sauthentication\sfailed/ nocase ascii wide
                        $string7 = /\[\+\]\sHTTP\sClient\sAuth\sContext\sswapped\swith\sSYSTEM\s/ nocase ascii wide
                        $string8 = /\[\+\]\sHTTP\sreflected\sDCOM\sauthentication\ssucceeded\!/ nocase ascii wide
                        $string9 = /\[\+\]\sSMB\sreflected\sDCOM\sauthentication\ssucceeded\!/ nocase ascii wide
                        $string10 = /\[\+\]\sSMB\sreflected\sDCOM\sauthentication\ssucceeded\!/ nocase ascii wide
                        $string11 = /\\evil\.dll/ nocase ascii wide
                        $string12 = /\\LocalPotato\\.{0,1000}\.cpp/ nocase ascii wide
                        $string13 = /\\LocalPotato\\.{0,1000}\.exe/ nocase ascii wide
                        $string14 = /\\PotatoTrigger\.cpp/ nocase ascii wide
                        $string15 = /\]\sReceived\sDCOM\sNTLM\stype\s3\sauthentication\sfrom\sthe\sprivileged\sclient/ nocase ascii wide
                        $string16 = "1B3C96A3-F698-472B-B786-6FED7A205159" nocase ascii wide
                        $string17 = "-c 854A20FB-2D44-457D-992F-EF13785D2B51" nocase ascii wide
                        $string18 = /DCOMReflection\.cpp/ nocase ascii wide
                        $string19 = "decoder-it/LocalPotato" nocase ascii wide
                        $string20 = /IUnknownObj\.cpp/ nocase ascii wide
                        $string21 = /LocalPotato\s\(aka\sCVE\-2023\-21746\s\&\sHTTP\/WebDAV\)/ nocase ascii wide
                        $string22 = "localpotato -i" nocase ascii wide
                        $string23 = /LocalPotato\.cpp/ nocase ascii wide
                        $string24 = /LocalPotato\.exe/ nocase ascii wide
                        $string25 = /LocalPotato\.html/ nocase ascii wide
                        $string26 = /LocalPotato\.sln/ nocase ascii wide
                        $string27 = /LocalPotato\.vcxproj/ nocase ascii wide
                        $string28 = /LocalPotato\.zip/ nocase ascii wide
                        $string29 = "LocalPotato-master" nocase ascii wide

    condition:
        any of them
}