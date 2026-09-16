rule tor2web
{
    meta:
        description = "Detection patterns for the tool 'tor2web' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tor2web"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " install tor2web" nocase ascii wide
                        $string2 = /\st2w\.py/ nocase ascii wide
                        $string3 = "# socksport = 9050" nocase ascii wide
                        $string4 = /\.tor2web\s/ nocase ascii wide
                        $string5 = "/bin/tor2web"
                        $string6 = /\/etc\/init\.d\/tor/
                        $string7 = /\/etc\/init\.d\/tor2web/
                        $string8 = "/home/tor2web/"
                        $string9 = /\/t2w\.py/
                        $string10 = /\/Tor2web\-.{0,1000}\.tar\.gz/ nocase ascii wide
                        $string11 = /\/Tor2web\-.{0,1000}\.zip/ nocase ascii wide
                        $string12 = /\/tor2web\.conf/
                        $string13 = /\/Tor2web\.git/ nocase ascii wide
                        $string14 = /\/tor2web\.js/ nocase ascii wide
                        $string15 = ">Tor2web Error: " nocase ascii wide
                        $string16 = "5529ff4b4c60d1cfefb02f145e149ffb166229e03aff4d8917340190753cde9e" nocase ascii wide
                        $string17 = "87c4041617fc7010b7e20630ae48cc8c17dc84cd6fb5c330f0bc92af52baa2fa" nocase ascii wide
                        $string18 = "a276ed1739c3380b2e918da23ddac04cc117e17e08dac219bb4f82783f9f9850" nocase ascii wide
                        $string19 = "a6479f37d1ab80d878c949e10b1b44cd7714c87a67da40c438237af0501de51f" nocase ascii wide
                        $string20 = "Adding GlobaLeaks PGP key to trusted APT keys" nocase ascii wide
                        $string21 = /apt\sinstall\s.{0,1000}tor2web/ nocase ascii wide
                        $string22 = /apt\-get\sinstall\s.{0,1000}tor2web/ nocase ascii wide
                        $string23 = /class\sT2WRPCServer\(/ nocase ascii wide
                        $string24 = "dist-packages/tor2web/" nocase ascii wide
                        $string25 = "from tor2web import" nocase ascii wide
                        $string26 = "globaleaks/Tor2web" nocase ascii wide
                        $string27 = "href=\"\"/\"\">tor2web</a>" nocase ascii wide
                        $string28 = /http\:\/\/tor2web\./ nocase ascii wide
                        $string29 = /https\:\/\/tor2web\./ nocase ascii wide
                        $string30 = /info\@tor2web\.org/ nocase ascii wide
                        $string31 = /install\-tor2web\.sh/ nocase ascii wide
                        $string32 = /lists\.tor2web\.org/ nocase ascii wide
                        $string33 = "OFTC/tor2web/" nocase ascii wide
                        $string34 = /remote_get_tor_exits_list\(/ nocase ascii wide
                        $string35 = /spawnT2W\(/ nocase ascii wide
                        $string36 = "Start the Tor2web proxy" nocase ascii wide
                        $string37 = /Starting\stor\s\(via\ssystemctl\)/ nocase ascii wide
                        $string38 = "tor2web start" nocase ascii wide
                        $string39 = "tor2web stop" nocase ascii wide
                        $string40 = /tor2web\.pid/ nocase ascii wide
                        $string41 = /tor2web\.service/ nocase ascii wide
                        $string42 = "tor2web/Tor2web" nocase ascii wide
                        $string43 = "tor2web_notification_form" nocase ascii wide
                        $string44 = /tor2web\-cert\.pem/ nocase ascii wide
                        $string45 = /tor2web\-default\.conf/ nocase ascii wide
                        $string46 = /tor2web\-dh\.pem/ nocase ascii wide
                        $string47 = /tor2web\-globaleaks\.conf/ nocase ascii wide
                        $string48 = "tor2web-hidden" nocase ascii wide
                        $string49 = /tor2web\-intermediate\.pem/ nocase ascii wide
                        $string50 = /tor2web\-key\.pem/ nocase ascii wide
                        $string51 = "tor2web-visible" nocase ascii wide
                        $string52 = /update\-rc\.d\stor2web\sdefaults/ nocase ascii wide
                        $string53 = /www\.tor2web\.org/ nocase ascii wide

    condition:
        any of them
}