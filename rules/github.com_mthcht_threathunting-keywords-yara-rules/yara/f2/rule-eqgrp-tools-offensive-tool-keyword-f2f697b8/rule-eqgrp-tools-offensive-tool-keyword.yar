rule rule_EQGRP_tools_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'EQGRP tools' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EQGRP tools"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_EQGRP_tools_offensive_tool_keyword = /\<\s\/dev\/console\s\|\suudecode\s\&\&\suncompress/ nocase ascii wide
                        $string2_EQGRP_tools_offensive_tool_keyword = /\>\s\/var\/log\/audit\/audit\.log.{0,1000}\srm\s\-f\s\./
                        $string3_EQGRP_tools_offensive_tool_keyword = /127\.0\.0\.1\sis\snot\sadvisable\sas\sa\ssource\.\sUse\s\-l\s127\.0\.0\.1\sto\soverride\sthis\swarning/ nocase ascii wide
                        $string4_EQGRP_tools_offensive_tool_keyword = /Attempting\sconnection\sfrom\s0\.0\.0\.0\:/ nocase ascii wide
                        $string5_EQGRP_tools_offensive_tool_keyword = /Auditcleaner\./ nocase ascii wide
                        $string6_EQGRP_tools_offensive_tool_keyword = /cat\s\>\s\/dev\/tcp\/127\.0\.0\.1.{0,1000}\<\<END/ nocase ascii wide
                        $string7_EQGRP_tools_offensive_tool_keyword = "chmod 666 /var/run/utmp~"
                        $string8_EQGRP_tools_offensive_tool_keyword = "chmod 700 nscd crond"
                        $string9_EQGRP_tools_offensive_tool_keyword = /cp\s\/var\/log\/audit\/audit\.log\s\.tmp/
                        $string10_EQGRP_tools_offensive_tool_keyword = "dubmoat" nocase ascii wide
                        $string11_EQGRP_tools_offensive_tool_keyword = "Dubmoat_ExtractData" nocase ascii wide
                        $string12_EQGRP_tools_offensive_tool_keyword = "Dubmoat_PrintFilename" nocase ascii wide
                        $string13_EQGRP_tools_offensive_tool_keyword = "Dubmoat_TruncateFile" nocase ascii wide
                        $string14_EQGRP_tools_offensive_tool_keyword = "echowrecker"
                        $string15_EQGRP_tools_offensive_tool_keyword = /emptybowl\.py/ nocase ascii wide
                        $string16_EQGRP_tools_offensive_tool_keyword = "ewok -t " nocase ascii wide
                        $string17_EQGRP_tools_offensive_tool_keyword = "ftshell -" nocase ascii wide
                        $string18_EQGRP_tools_offensive_tool_keyword = /ftshell\.v3/ nocase ascii wide
                        $string19_EQGRP_tools_offensive_tool_keyword = /ghost_.{0,1000}\s\-v/ nocase ascii wide
                        $string20_EQGRP_tools_offensive_tool_keyword = "ghost_sparc" nocase ascii wide
                        $string21_EQGRP_tools_offensive_tool_keyword = "ghost_x86" nocase ascii wide
                        $string22_EQGRP_tools_offensive_tool_keyword = /iptables\s\-\%c\sOUTPUT\s\-p\stcp\s\-d\s127\.0\.0\.1\s\-\-tcp\-flags\sRST\sRST\s\-j\sDROP\s/ nocase ascii wide
                        $string23_EQGRP_tools_offensive_tool_keyword = "noclient: failed to execute %s: %s" nocase ascii wide
                        $string24_EQGRP_tools_offensive_tool_keyword = "ourtn-ftshell-upcommand" nocase ascii wide
                        $string25_EQGRP_tools_offensive_tool_keyword = /send\s\\.{0,1000}\\\[\s\\\\.{0,1000}\\\$BASH\\\\.{0,1000}\s\=\s\\\\.{0,1000}\/bin\/bash\\\\.{0,1000}\s\-o\s\\\\.{0,1000}\\\$SHELL\\\\.{0,1000}\s\=\s\\\\.{0,1000}\/bin\/bash\\\\.{0,1000}\s\\\]/
                        $string26_EQGRP_tools_offensive_tool_keyword = /sendmail\s\-osendmail\schmod\s\+x\ssendmail/
                        $string27_EQGRP_tools_offensive_tool_keyword = /sh\s\-c\s.{0,1000}ping\s\-c\s2\s\%s\s\sgrep\s\%s\s\/proc\/net\/arp\s\>\/tmp\/gx\s/ nocase ascii wide
                        $string28_EQGRP_tools_offensive_tool_keyword = /system\srm\s\-f\s\/current\/tmp\/ftshell\.latest/ nocase ascii wide
                        $string29_EQGRP_tools_offensive_tool_keyword = /usr\/bin\/wget\s\-O\s\/tmp\/a\shttp.{0,1000}\schmod\s755\s\/tmp\/cron/
                        $string30_EQGRP_tools_offensive_tool_keyword = /noclient\-3\./

    condition:
        any of them
}