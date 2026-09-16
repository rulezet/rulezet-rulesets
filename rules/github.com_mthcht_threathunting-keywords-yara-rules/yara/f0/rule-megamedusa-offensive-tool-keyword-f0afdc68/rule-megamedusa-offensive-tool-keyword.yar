rule rule_MegaMedusa_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'MegaMedusa' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MegaMedusa"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_MegaMedusa_offensive_tool_keyword = "//Don't Recode & Decrypt it Niggas" nocase ascii wide
                        $string2_MegaMedusa_offensive_tool_keyword = "//MegaMedusa-DDoS-Machine" nocase ascii wide
                        $string3_MegaMedusa_offensive_tool_keyword = "685e710dd49930b791f10fe68c46a2eae0ecdd93191ceb459425b338a0980844" nocase ascii wide
                        $string4_MegaMedusa_offensive_tool_keyword = "777d789fe076804229d09cae4fd8abbab955c683ccc11195639b88cc6567786b" nocase ascii wide
                        $string5_MegaMedusa_offensive_tool_keyword = "a5c8d558af0e8e3853cdd03be91dc7d915113a291466383005dbe1951809f663" nocase ascii wide
                        $string6_MegaMedusa_offensive_tool_keyword = /com\/Anonym0usWork1221\/Free\-Proxies\/main\/proxy_files\/http_proxies\.txt/ nocase ascii wide
                        $string7_MegaMedusa_offensive_tool_keyword = /com\/Anonym0usWork1221\/Free\-Proxies\/main\/proxy_files\/https_proxies\.txt/ nocase ascii wide
                        $string8_MegaMedusa_offensive_tool_keyword = /com\/mmpx12\/proxy\-list\/master\/https\.txt/ nocase ascii wide
                        $string9_MegaMedusa_offensive_tool_keyword = /com\/monosans\/proxy\-list\/main\/proxies\/http\.txt/ nocase ascii wide
                        $string10_MegaMedusa_offensive_tool_keyword = /com\/MuRongPIG\/Proxy\-Master\/main\/http\.txt/ nocase ascii wide
                        $string11_MegaMedusa_offensive_tool_keyword = /com\/officialputuid\/KangProxy\/KangProxy\/http\/http\.txt/ nocase ascii wide
                        $string12_MegaMedusa_offensive_tool_keyword = /com\/opsxcq\/proxy\-list\/master\/list\.txt/ nocase ascii wide
                        $string13_MegaMedusa_offensive_tool_keyword = /com\/proxylist\-to\/proxy\-list\/main\/http\.txt/ nocase ascii wide
                        $string14_MegaMedusa_offensive_tool_keyword = /com\/prxchk\/proxy\-list\/main\/http\.txt/ nocase ascii wide
                        $string15_MegaMedusa_offensive_tool_keyword = /com\/roosterkid\/openproxylist\/main\/HTTPS_RAW\.txt/ nocase ascii wide
                        $string16_MegaMedusa_offensive_tool_keyword = /com\/ShiftyTR\/Proxy\-List\/master\/http\.txt/ nocase ascii wide
                        $string17_MegaMedusa_offensive_tool_keyword = /com\/ShiftyTR\/Proxy\-List\/master\/https\.txt/ nocase ascii wide
                        $string18_MegaMedusa_offensive_tool_keyword = /com\/TheSpeedX\/PROXY\-List\/master\/http\.txt/ nocase ascii wide
                        $string19_MegaMedusa_offensive_tool_keyword = /com\/yuceltoluyag\/GoodProxy\/main\/raw\.txt/ nocase ascii wide
                        $string20_MegaMedusa_offensive_tool_keyword = /http\:\/\/go\.mail\.ru\/search\?gay\.ru\.query\=1\&q\=\?abc\.r\&q\=/ nocase ascii wide
                        $string21_MegaMedusa_offensive_tool_keyword = /http\:\/\/king\-hrdevil\.rhcloud\.com\/f5ddos3\.html\?v\=/ nocase ascii wide
                        $string22_MegaMedusa_offensive_tool_keyword = /http\:\/\/louis\-ddosvn\.rhcloud\.com\/f5\.html\?v\=/ nocase ascii wide
                        $string23_MegaMedusa_offensive_tool_keyword = /http\:\/\/nova\.rambler\.ru\/search\?btnG\=\%D0\%9D\%\?D0\%B0\%D0\%B\&q\=/ nocase ascii wide
                        $string24_MegaMedusa_offensive_tool_keyword = /http\:\/\/page\-xirusteam\.rhcloud\.com\/f5ddos3\.html\?v\=/ nocase ascii wide
                        $string25_MegaMedusa_offensive_tool_keyword = /http\:\/\/php\-hrdevil\.rhcloud\.com\/f5ddos3\.html\?v\=/ nocase ascii wide
                        $string26_MegaMedusa_offensive_tool_keyword = /https\:\/\/codeberg\.org\/RipperSec\/MegaMedusa/ nocase ascii wide
                        $string27_MegaMedusa_offensive_tool_keyword = /https\:\/\/t\.me\/MegaMedusaLog/ nocase ascii wide
                        $string28_MegaMedusa_offensive_tool_keyword = /MegaMedusa\\x20Attacking/ nocase ascii wide
                        $string29_MegaMedusa_offensive_tool_keyword = /t\.me\/RipperSec\\x20\\x20\\x20\\x20\\x20\\x20\\x1b/ nocase ascii wide

    condition:
        any of them
}