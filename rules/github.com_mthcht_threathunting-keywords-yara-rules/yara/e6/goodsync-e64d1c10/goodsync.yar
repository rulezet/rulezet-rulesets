rule Goodsync
{
    meta:
        description = "Detection patterns for the tool 'Goodsync' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Goodsync"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/GoodSync\-vsub\-Setup\.exe/ nocase ascii wide
                        $string2 = /\\CurrentControlSet\\Services\\GsServer/ nocase ascii wide
                        $string3 = /\\DIRECTORY\\BACKGROUND\\SHELL\\GOODSYNC/ nocase ascii wide
                        $string4 = /\\GoodSync\-2.{0,1000}\-.{0,1000}\.log/ nocase ascii wide
                        $string5 = /\\GOODSYNC2GO\.EXE/ nocase ascii wide
                        $string6 = /\\GOODSYNC2GO\-V.{0,1000}\.EXE/ nocase ascii wide
                        $string7 = /\\GoodSync\-vsub\-Setup\.exe/ nocase ascii wide
                        $string8 = /\\gs\-runner\.exe/ nocase ascii wide
                        $string9 = /\\GS\-SERVER\.EXE/ nocase ascii wide
                        $string10 = /\\Program\sFiles\\SIBER\sSYSTEMS\\GOODSYNC\\/ nocase ascii wide
                        $string11 = /\\Siber\sSystems\\GoodSync\\/ nocase ascii wide
                        $string12 = /\\Users\\.{0,1000}\\AppData\\Local\\GoodSync/ nocase ascii wide
                        $string13 = ">GoodSync<" nocase ascii wide
                        $string14 = /\>gs\-runner\.exe\</ nocase ascii wide
                        $string15 = /Copy\sNew\s.{0,1000}gdrive\:\/\/www\.googleapis\.com\/GS_Sync\// nocase ascii wide
                        $string16 = /Copy\sNew\s.{0,1000}sftp\:\/\// nocase ascii wide
                        $string17 = "GoodSync Server" nocase ascii wide
                        $string18 = /GoodSync\-vsub\-2Go\-Setup\.exe/ nocase ascii wide
                        $string19 = /mediator\.goodsync\.com/ nocase ascii wide
                        $string20 = /Program\sFiles\\Siber\sSystems\\GoodSync/ nocase ascii wide
                        $string21 = /SOFTWARE\\Siber\sSystems\\GoodSync\\Profiles/ nocase ascii wide
                        $string22 = /temp.{0,1000}\\gsync\.exe/ nocase ascii wide

    condition:
        any of them
}