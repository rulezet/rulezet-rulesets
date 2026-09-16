rule rule_tor2web_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'tor2web' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tor2web"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_tor2web_offensive_tool_keyword = " install tor2web" nocase ascii wide
                        $string2_tor2web_offensive_tool_keyword = /\st2w\.py/ nocase ascii wide
                        $string3_tor2web_offensive_tool_keyword = "# socksport = 9050" nocase ascii wide
                        $string4_tor2web_offensive_tool_keyword = /\.tor2web\s/ nocase ascii wide
                        $string5_tor2web_offensive_tool_keyword = "/bin/tor2web"
                        $string6_tor2web_offensive_tool_keyword = /\/etc\/init\.d\/tor/
                        $string7_tor2web_offensive_tool_keyword = /\/etc\/init\.d\/tor2web/
                        $string8_tor2web_offensive_tool_keyword = "/home/tor2web/"
                        $string9_tor2web_offensive_tool_keyword = /\/t2w\.py/
                        $string10_tor2web_offensive_tool_keyword = /\/Tor2web\-.{0,1000}\.tar\.gz/ nocase ascii wide
                        $string11_tor2web_offensive_tool_keyword = /\/Tor2web\-.{0,1000}\.zip/ nocase ascii wide
                        $string12_tor2web_offensive_tool_keyword = /\/tor2web\.conf/
                        $string13_tor2web_offensive_tool_keyword = /\/Tor2web\.git/ nocase ascii wide
                        $string14_tor2web_offensive_tool_keyword = /\/tor2web\.js/ nocase ascii wide
                        $string15_tor2web_offensive_tool_keyword = ">Tor2web Error: " nocase ascii wide
                        $string16_tor2web_offensive_tool_keyword = "5529ff4b4c60d1cfefb02f145e149ffb166229e03aff4d8917340190753cde9e" nocase ascii wide
                        $string17_tor2web_offensive_tool_keyword = "87c4041617fc7010b7e20630ae48cc8c17dc84cd6fb5c330f0bc92af52baa2fa" nocase ascii wide
                        $string18_tor2web_offensive_tool_keyword = "a276ed1739c3380b2e918da23ddac04cc117e17e08dac219bb4f82783f9f9850" nocase ascii wide
                        $string19_tor2web_offensive_tool_keyword = "a6479f37d1ab80d878c949e10b1b44cd7714c87a67da40c438237af0501de51f" nocase ascii wide
                        $string20_tor2web_offensive_tool_keyword = "Adding GlobaLeaks PGP key to trusted APT keys" nocase ascii wide
                        $string21_tor2web_offensive_tool_keyword = /apt\sinstall\s.{0,1000}tor2web/ nocase ascii wide
                        $string22_tor2web_offensive_tool_keyword = /apt\-get\sinstall\s.{0,1000}tor2web/ nocase ascii wide
                        $string23_tor2web_offensive_tool_keyword = /class\sT2WRPCServer\(/ nocase ascii wide
                        $string24_tor2web_offensive_tool_keyword = "dist-packages/tor2web/" nocase ascii wide
                        $string25_tor2web_offensive_tool_keyword = "from tor2web import" nocase ascii wide
                        $string26_tor2web_offensive_tool_keyword = "globaleaks/Tor2web" nocase ascii wide
                        $string27_tor2web_offensive_tool_keyword = "href=\"\"/\"\">tor2web</a>" nocase ascii wide
                        $string28_tor2web_offensive_tool_keyword = /http\:\/\/tor2web\./ nocase ascii wide
                        $string29_tor2web_offensive_tool_keyword = /https\:\/\/tor2web\./ nocase ascii wide
                        $string30_tor2web_offensive_tool_keyword = /info\@tor2web\.org/ nocase ascii wide
                        $string31_tor2web_offensive_tool_keyword = /install\-tor2web\.sh/ nocase ascii wide
                        $string32_tor2web_offensive_tool_keyword = /lists\.tor2web\.org/ nocase ascii wide
                        $string33_tor2web_offensive_tool_keyword = "OFTC/tor2web/" nocase ascii wide
                        $string34_tor2web_offensive_tool_keyword = /remote_get_tor_exits_list\(/ nocase ascii wide
                        $string35_tor2web_offensive_tool_keyword = /spawnT2W\(/ nocase ascii wide
                        $string36_tor2web_offensive_tool_keyword = "Start the Tor2web proxy" nocase ascii wide
                        $string37_tor2web_offensive_tool_keyword = /Starting\stor\s\(via\ssystemctl\)/ nocase ascii wide
                        $string38_tor2web_offensive_tool_keyword = "tor2web start" nocase ascii wide
                        $string39_tor2web_offensive_tool_keyword = "tor2web stop" nocase ascii wide
                        $string40_tor2web_offensive_tool_keyword = /tor2web\.pid/ nocase ascii wide
                        $string41_tor2web_offensive_tool_keyword = /tor2web\.service/ nocase ascii wide
                        $string42_tor2web_offensive_tool_keyword = "tor2web/Tor2web" nocase ascii wide
                        $string43_tor2web_offensive_tool_keyword = "tor2web_notification_form" nocase ascii wide
                        $string44_tor2web_offensive_tool_keyword = /tor2web\-cert\.pem/ nocase ascii wide
                        $string45_tor2web_offensive_tool_keyword = /tor2web\-default\.conf/ nocase ascii wide
                        $string46_tor2web_offensive_tool_keyword = /tor2web\-dh\.pem/ nocase ascii wide
                        $string47_tor2web_offensive_tool_keyword = /tor2web\-globaleaks\.conf/ nocase ascii wide
                        $string48_tor2web_offensive_tool_keyword = "tor2web-hidden" nocase ascii wide
                        $string49_tor2web_offensive_tool_keyword = /tor2web\-intermediate\.pem/ nocase ascii wide
                        $string50_tor2web_offensive_tool_keyword = /tor2web\-key\.pem/ nocase ascii wide
                        $string51_tor2web_offensive_tool_keyword = "tor2web-visible" nocase ascii wide
                        $string52_tor2web_offensive_tool_keyword = /update\-rc\.d\stor2web\sdefaults/ nocase ascii wide
                        $string53_tor2web_offensive_tool_keyword = /www\.tor2web\.org/ nocase ascii wide

    condition:
        any of them
}