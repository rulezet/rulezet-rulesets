rule CursedChrome
{
    meta:
        description = "Detection patterns for the tool 'CursedChrome' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CursedChrome"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/CursedChrome\.git/ nocase ascii wide
                        $string2 = /\/extension_injection\.sh/ nocase ascii wide
                        $string3 = /\/redirect\-hack\.html\?id\=/ nocase ascii wide
                        $string4 = /127\.0\.0\.1\:8118/ nocase ascii wide
                        $string5 = "A new browser has connected to us via WebSocket!" nocase ascii wide
                        $string6 = /bash\sextension_injection\.sh/
                        $string7 = "const subscription_id = `TOPROXY_" nocase ascii wide
                        $string8 = /COPY\sanyproxy\/\s\.\/anyproxy\//
                        $string9 = "CursedChrome API server is now listening on port" nocase ascii wide
                        $string10 = "CursedChrome WebSocket server is now running on port" nocase ascii wide
                        $string11 = /CursedChrome\-master\.zip/ nocase ascii wide
                        $string12 = "DATABASE_PASSWORD: cursedchrome" nocase ascii wide
                        $string13 = "DATABASE_USER: cursedchrome" nocase ascii wide
                        $string14 = /docker\simages\s\|\sgrep\scursed/ nocase ascii wide
                        $string15 = /docker\sps\s\-a\s\|\sgrep\scursed/ nocase ascii wide
                        $string16 = "docker-compose up cursedchrome" nocase ascii wide
                        $string17 = "http://localhost:8118" nocase ascii wide
                        $string18 = /logit\(\`New\ssubscriber\:\sTOBROWSER__/ nocase ascii wide
                        $string19 = "mandatoryprogrammer/CursedChrome" nocase ascii wide
                        $string20 = /new\sWebSocket\(\\"ws\:\/\/127\.0\.0\.1\:4343\\"\)/ nocase ascii wide
                        $string21 = /publisher\.publish\(\`TOBROWSER_/ nocase ascii wide
                        $string22 = /Wat\,\sthis\sshouldn\'t\shappen\?\sOrphaned\smessage\s\(somebody\smight\sbe\sprobing\syou\!\)\:/ nocase ascii wide

    condition:
        any of them
}