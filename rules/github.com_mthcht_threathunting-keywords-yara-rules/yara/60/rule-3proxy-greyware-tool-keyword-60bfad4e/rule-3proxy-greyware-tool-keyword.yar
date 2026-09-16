rule rule__3proxy_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool '3proxy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "3proxy"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1__3proxy_greyware_tool_keyword = /\/3proxy\-.{0,1000}\.deb/ nocase ascii wide
                        $string2__3proxy_greyware_tool_keyword = /\/3proxy\-.{0,1000}\.rpm/ nocase ascii wide
                        $string3__3proxy_greyware_tool_keyword = /\/3proxy\-.{0,1000}\.zip/ nocase ascii wide
                        $string4__3proxy_greyware_tool_keyword = /\/3proxy\.exe/ nocase ascii wide
                        $string5__3proxy_greyware_tool_keyword = /\/3proxy\.git/ nocase ascii wide
                        $string6__3proxy_greyware_tool_keyword = /\/3proxy\.log/
                        $string7__3proxy_greyware_tool_keyword = "/etc/3proxy/conf"
                        $string8__3proxy_greyware_tool_keyword = /\\3proxy\-.{0,1000}\.deb/ nocase ascii wide
                        $string9__3proxy_greyware_tool_keyword = /\\3proxy\-.{0,1000}\.rpm/ nocase ascii wide
                        $string10__3proxy_greyware_tool_keyword = /\\3proxy\-.{0,1000}\.zip/ nocase ascii wide
                        $string11__3proxy_greyware_tool_keyword = /\\3proxy\.cfg/ nocase ascii wide
                        $string12__3proxy_greyware_tool_keyword = /\\3proxy\.exe/ nocase ascii wide
                        $string13__3proxy_greyware_tool_keyword = /\\3proxy\.key/ nocase ascii wide
                        $string14__3proxy_greyware_tool_keyword = /\\3proxy\.log/ nocase ascii wide
                        $string15__3proxy_greyware_tool_keyword = /\\bin\\3proxy/ nocase ascii wide
                        $string16__3proxy_greyware_tool_keyword = /128s3proxy\.key\\"/ nocase ascii wide
                        $string17__3proxy_greyware_tool_keyword = "3proxy --install" nocase ascii wide
                        $string18__3proxy_greyware_tool_keyword = "3proxy --remove" nocase ascii wide
                        $string19__3proxy_greyware_tool_keyword = "3proxy tiny proxy server" nocase ascii wide
                        $string20__3proxy_greyware_tool_keyword = "3proxy Windows Authentication plugin" nocase ascii wide
                        $string21__3proxy_greyware_tool_keyword = /3proxy\.exe\s\-\-/ nocase ascii wide
                        $string22__3proxy_greyware_tool_keyword = /3proxy\.service/ nocase ascii wide
                        $string23__3proxy_greyware_tool_keyword = "3proxy/3proxy" nocase ascii wide
                        $string24__3proxy_greyware_tool_keyword = /3proxy\@3proxy\.org/ nocase ascii wide
                        $string25__3proxy_greyware_tool_keyword = /add3proxyuser\.sh/ nocase ascii wide

    condition:
        any of them
}