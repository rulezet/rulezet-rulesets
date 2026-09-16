rule rule_Goodsync_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Goodsync' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Goodsync"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Goodsync_greyware_tool_keyword = /\/GoodSync\-vsub\-Setup\.exe/ nocase ascii wide
                        $string2_Goodsync_greyware_tool_keyword = /\\CurrentControlSet\\Services\\GsServer/ nocase ascii wide
                        $string3_Goodsync_greyware_tool_keyword = /\\DIRECTORY\\BACKGROUND\\SHELL\\GOODSYNC/ nocase ascii wide
                        $string4_Goodsync_greyware_tool_keyword = /\\GoodSync\-2.{0,1000}\-.{0,1000}\.log/ nocase ascii wide
                        $string5_Goodsync_greyware_tool_keyword = /\\GOODSYNC2GO\.EXE/ nocase ascii wide
                        $string6_Goodsync_greyware_tool_keyword = /\\GOODSYNC2GO\-V.{0,1000}\.EXE/ nocase ascii wide
                        $string7_Goodsync_greyware_tool_keyword = /\\GoodSync\-vsub\-Setup\.exe/ nocase ascii wide
                        $string8_Goodsync_greyware_tool_keyword = /\\gs\-runner\.exe/ nocase ascii wide
                        $string9_Goodsync_greyware_tool_keyword = /\\GS\-SERVER\.EXE/ nocase ascii wide
                        $string10_Goodsync_greyware_tool_keyword = /\\Program\sFiles\\SIBER\sSYSTEMS\\GOODSYNC\\/ nocase ascii wide
                        $string11_Goodsync_greyware_tool_keyword = /\\Siber\sSystems\\GoodSync\\/ nocase ascii wide
                        $string12_Goodsync_greyware_tool_keyword = /\\Users\\.{0,1000}\\AppData\\Local\\GoodSync/ nocase ascii wide
                        $string13_Goodsync_greyware_tool_keyword = ">GoodSync<" nocase ascii wide
                        $string14_Goodsync_greyware_tool_keyword = /\>gs\-runner\.exe\</ nocase ascii wide
                        $string15_Goodsync_greyware_tool_keyword = /Copy\sNew\s.{0,1000}gdrive\:\/\/www\.googleapis\.com\/GS_Sync\// nocase ascii wide
                        $string16_Goodsync_greyware_tool_keyword = /Copy\sNew\s.{0,1000}sftp\:\/\// nocase ascii wide
                        $string17_Goodsync_greyware_tool_keyword = "GoodSync Server" nocase ascii wide
                        $string18_Goodsync_greyware_tool_keyword = /GoodSync\-vsub\-2Go\-Setup\.exe/ nocase ascii wide
                        $string19_Goodsync_greyware_tool_keyword = /mediator\.goodsync\.com/ nocase ascii wide
                        $string20_Goodsync_greyware_tool_keyword = /Program\sFiles\\Siber\sSystems\\GoodSync/ nocase ascii wide
                        $string21_Goodsync_greyware_tool_keyword = /SOFTWARE\\Siber\sSystems\\GoodSync\\Profiles/ nocase ascii wide
                        $string22_Goodsync_greyware_tool_keyword = /temp.{0,1000}\\gsync\.exe/ nocase ascii wide

    condition:
        any of them
}