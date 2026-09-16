rule blackarch
{
    meta:
        description = "Detection patterns for the tool 'blackarch' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "blackarch"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/tmp/blackarch" nocase ascii wide
                        $string2 = /au\.mirrors\.cicku\.me\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string3 = /blackarch\.cs\.nycu\.edu\.tw\/.{0,1000}\/os\// nocase ascii wide
                        $string4 = /blackarch\.leneveu\.fr\/.{0,1000}\/os\// nocase ascii wide
                        $string5 = /blackarch\.mirror\.digitalpacific\.com\.au\/.{0,1000}\/os\// nocase ascii wide
                        $string6 = /blackarch\.mirror\.garr\.it\/mirrors\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string7 = /blackarch\.org\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string8 = /blackarch\.org\/blackarch\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string9 = /blackarch\.unixpeople\.org\/.{0,1000}\/os\// nocase ascii wide
                        $string10 = /ca\.mirrors\.cicku\.me\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string11 = /de\.mirrors\.cicku\.me\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string12 = /distro\.ibiblio\.org\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string13 = /download\.nus\.edu\.sg\/mirror\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string14 = /eu\.mirrors\.cicku\.me\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string15 = /ftp\.cc\.uoc\.gr\/mirrors\/linux\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string16 = /ftp\.halifax\.rwth\-aachen\.de\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string17 = /ftp\.icm\.edu\.pl\/pub\/Linux\/dist\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string18 = /ftp\.kddilabs\.jp\/Linux\/packages\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string19 = /ftp\.linux\.org\.tr\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string20 = /http\:\/\/mirror\.archlinux\.no/ nocase ascii wide
                        $string21 = /https\:\/\/raw\.githubusercontent\.com\/BlackArch\/blackarch\/master\/mirror\/mirror\.lst/ nocase ascii wide
                        $string22 = /https\:\/\/www\.blackarch\.org\/blackarch\/blackarch\/lastupdate/ nocase ascii wide
                        $string23 = /in\.mirrors\.cicku\.me\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string24 = /jp\.mirrors\.cicku\.me\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string25 = /kr\.mirrors\.cicku\.me\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string26 = /md\.mirrors\.hacktegic\.com\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string27 = /mirror\.archlinux\.tw\/BlackArch\/.{0,1000}\/os\// nocase ascii wide
                        $string28 = /mirror\.cedia\.org\.ec\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string29 = /mirror\.cyberbits\.eu\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string30 = /mirror\.easyname\.at\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string31 = /mirror\.easyname\.ch\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string32 = /mirror\.maa\.albony\.in\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string33 = /mirror\.math\.princeton\.edu\/pub\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string34 = /mirror\.serverion\.com\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string35 = /mirror\.sg\.gs\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string36 = /mirror\.sjtu\.edu\.cn\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string37 = /mirror\.team\-cymru\.com\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string38 = /mirror\.telepoint\.bg\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string39 = /mirror\.tillo\.ch\/ftp\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string40 = /mirror\.yandex\.ru\/mirrors\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string41 = /mirror\.zetup\.net\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string42 = /mirrors\.aliyun\.com\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string43 = /mirrors\.cicku\.me\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string44 = /mirrors\.dotsrc\.org\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string45 = /mirrors\.gethosted\.online\/blackarch\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string46 = /mirrors\.hostico\.ro\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string47 = /mirrors\.hust\.edu\.cn\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string48 = /mirrors\.nju\.edu\.cn\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string49 = /mirrors\.ocf\.berkeley\.edu\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string50 = /mirrors\.tuna\.tsinghua\.edu\.cn\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string51 = /mirrors\.ustc\.edu\.cn\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string52 = /quantum\-mirror\.hu\/mirrors\/pub\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string53 = /repository\.su\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string54 = /sg\.mirrors\.cicku\.me\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string55 = /us\.mirrors\.cicku\.me\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string56 = /www\.ftp\.ne\.jp\/Linux\/packages\/blackarch\/.{0,1000}\/os\// nocase ascii wide
                        $string57 = /www\.mirrorservice\.org\/sites\/blackarch\.org\/blackarch\/.{0,1000}\/os\// nocase ascii wide

    condition:
        any of them
}