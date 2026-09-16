rule EQGRP_tools
{
    meta:
        description = "Detection patterns for the tool 'EQGRP tools' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EQGRP tools"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\<\s\/dev\/console\s\|\suudecode\s\&\&\suncompress/ nocase ascii wide
                        $string2 = /\>\s\/var\/log\/audit\/audit\.log.{0,1000}\srm\s\-f\s\./
                        $string3 = /127\.0\.0\.1\sis\snot\sadvisable\sas\sa\ssource\.\sUse\s\-l\s127\.0\.0\.1\sto\soverride\sthis\swarning/ nocase ascii wide
                        $string4 = /Attempting\sconnection\sfrom\s0\.0\.0\.0\:/ nocase ascii wide
                        $string5 = /Auditcleaner\./ nocase ascii wide
                        $string6 = /cat\s\>\s\/dev\/tcp\/127\.0\.0\.1.{0,1000}\<\<END/ nocase ascii wide
                        $string7 = "chmod 666 /var/run/utmp~"
                        $string8 = "chmod 700 nscd crond"
                        $string9 = /cp\s\/var\/log\/audit\/audit\.log\s\.tmp/
                        $string10 = "dubmoat" nocase ascii wide
                        $string11 = "Dubmoat_ExtractData" nocase ascii wide
                        $string12 = "Dubmoat_PrintFilename" nocase ascii wide
                        $string13 = "Dubmoat_TruncateFile" nocase ascii wide
                        $string14 = "echowrecker"
                        $string15 = /emptybowl\.py/ nocase ascii wide
                        $string16 = "ewok -t " nocase ascii wide
                        $string17 = "ftshell -" nocase ascii wide
                        $string18 = /ftshell\.v3/ nocase ascii wide
                        $string19 = /ghost_.{0,1000}\s\-v/ nocase ascii wide
                        $string20 = "ghost_sparc" nocase ascii wide
                        $string21 = "ghost_x86" nocase ascii wide
                        $string22 = /iptables\s\-\%c\sOUTPUT\s\-p\stcp\s\-d\s127\.0\.0\.1\s\-\-tcp\-flags\sRST\sRST\s\-j\sDROP\s/ nocase ascii wide
                        $string23 = "noclient: failed to execute %s: %s" nocase ascii wide
                        $string24 = "ourtn-ftshell-upcommand" nocase ascii wide
                        $string25 = /send\s\\.{0,1000}\\\[\s\\\\.{0,1000}\\\$BASH\\\\.{0,1000}\s\=\s\\\\.{0,1000}\/bin\/bash\\\\.{0,1000}\s\-o\s\\\\.{0,1000}\\\$SHELL\\\\.{0,1000}\s\=\s\\\\.{0,1000}\/bin\/bash\\\\.{0,1000}\s\\\]/
                        $string26 = /sendmail\s\-osendmail\schmod\s\+x\ssendmail/
                        $string27 = /sh\s\-c\s.{0,1000}ping\s\-c\s2\s\%s\s\sgrep\s\%s\s\/proc\/net\/arp\s\>\/tmp\/gx\s/ nocase ascii wide
                        $string28 = /system\srm\s\-f\s\/current\/tmp\/ftshell\.latest/ nocase ascii wide
                        $string29 = /usr\/bin\/wget\s\-O\s\/tmp\/a\shttp.{0,1000}\schmod\s755\s\/tmp\/cron/
                        $string30 = /noclient\-3\./

    condition:
        any of them
}