rule _3proxy {
  meta:
    description   = "Detection patterns for the tool '3proxy' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "3proxy"
    rule_category = "greyware_tool_keyword"

  strings:
            $string1  = /\/3proxy\-.{0,1000}\.deb/ nocase ascii wide
            $string2  = /\/3proxy\-.{0,1000}\.rpm/ nocase ascii wide
            $string3  = /\/3proxy\-.{0,1000}\.zip/ nocase ascii wide
            $string4  = /\/3proxy\.exe/ nocase ascii wide
            $string5  = /\/3proxy\.git/ nocase ascii wide
            $string6  = /\/3proxy\.log/ nocase ascii wide
            $string7  = /\/etc\/3proxy\/conf/ nocase ascii wide
            $string8  = /\\3proxy\-.{0,1000}\.deb/ nocase ascii wide
            $string9  = /\\3proxy\-.{0,1000}\.rpm/ nocase ascii wide
            $string10 = /\\3proxy\-.{0,1000}\.zip/ nocase ascii wide
            $string11 = /\\3proxy\.cfg/ nocase ascii wide
            $string12 = /\\3proxy\.exe/ nocase ascii wide
            $string13 = /\\3proxy\.key/ nocase ascii wide
            $string14 = /\\3proxy\.log/ nocase ascii wide
            $string15 = /\\bin\\3proxy/ nocase ascii wide
            $string16 = /128s3proxy\.key\"/ nocase ascii wide
            $string17 = /3proxy\s\-\-install/ nocase ascii wide
            $string18 = /3proxy\s\-\-remove/ nocase ascii wide
            $string19 = /3proxy\stiny\sproxy\sserver/ nocase ascii wide
            $string20 = /3proxy\sWindows\sAuthentication\splugin/ nocase ascii wide
            $string21 = /3proxy\.exe\s\-\-/ nocase ascii wide
            $string22 = /3proxy\.service/ nocase ascii wide
            $string23 = /3proxy\/3proxy/ nocase ascii wide
            $string24 = /3proxy\@3proxy\.org/ nocase ascii wide
            $string25 = /add3proxyuser\.sh/ nocase ascii wide

  condition:
    any of them
}