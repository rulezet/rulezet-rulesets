rule rule_AutoSUID_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AutoSUID' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AutoSUID"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_AutoSUID_greyware_tool_keyword = /\spwn_tclsh\.me/ nocase ascii wide
                        $string2_AutoSUID_greyware_tool_keyword = /\sWe\shave\sfound\sat\sleast\s.{0,1000}\spotential\sSUID\sexploitable\sfile\(s\)/ nocase ascii wide
                        $string3_AutoSUID_greyware_tool_keyword = /\.\/capsh\s\-\-gid\=0\s\-\-uid\=0\s\-\-/
                        $string4_AutoSUID_greyware_tool_keyword = /\.\/chroot\s\/\s\/bin\/sh\s\-p/
                        $string5_AutoSUID_greyware_tool_keyword = /\.\/env\s\/bin\/sh\s\-p/
                        $string6_AutoSUID_greyware_tool_keyword = /\.\/expect\s\-c\s\'spawn\s\/bin\/sh\s\-p\;interact\'/
                        $string7_AutoSUID_greyware_tool_keyword = /\.\/flock\s\-u\s\/\s\/bin\/sh\s\-p/
                        $string8_AutoSUID_greyware_tool_keyword = /\.\/nice\s\/bin\/sh\s\-p/
                        $string9_AutoSUID_greyware_tool_keyword = /\.\/rview\s\-c\s\'\:py3\simport\sos.{0,1000}os\.execl\(\\\\"\/bin\/sh\\/
                        $string10_AutoSUID_greyware_tool_keyword = /\/ld\.so\s\/bin\/sh\s\-p/
                        $string11_AutoSUID_greyware_tool_keyword = "/perf stat /bin/sh -p"
                        $string12_AutoSUID_greyware_tool_keyword = /\/perl\s\-e\s\'exec\s\\\\"\/bin\/sh\\\\"/
                        $string13_AutoSUID_greyware_tool_keyword = /\/pwn_tclsh\.me/
                        $string14_AutoSUID_greyware_tool_keyword = /\/rvim\s\-c\s\'\:py3\simport\sos.{0,1000}os\.execl\(\\\\"\/bin\/sh\\/
                        $string15_AutoSUID_greyware_tool_keyword = "/sshpass /bin/sh -p"
                        $string16_AutoSUID_greyware_tool_keyword = "/stdbuf -i0 /bin/sh -p"
                        $string17_AutoSUID_greyware_tool_keyword = "/unshare -r /bin/sh"
                        $string18_AutoSUID_greyware_tool_keyword = /\/view\s\-c\s\'\:py3\simport\sos.{0,1000}os\.execl\(\\\\"\/bin\/sh\\/
                        $string19_AutoSUID_greyware_tool_keyword = /\/watch\s\-x\ssh\s\-c\s\'reset.{0,1000}\sexec\ssh\s1\>\&0\s2\>\&0/
                        $string20_AutoSUID_greyware_tool_keyword = "agetty -o -p -l /bin/sh -a root tty"
                        $string21_AutoSUID_greyware_tool_keyword = "cpulimit -l 100 -f -- /bin/sh -p"
                        $string22_AutoSUID_greyware_tool_keyword = /dmsetup\screate\sbase\s\<\<EOF.{0,1000}0\s3534848\slinear\s\/dev\/loop0\s94208.{0,1000}\sEOF.{0,1000}\.\/dmsetup\sls\s\-\-exec\s\'\/bin\/sh\s\-p\s\-s/
                        $string23_AutoSUID_greyware_tool_keyword = "docker run -v /:/mnt --rm -it alpine chroot /mnt sh" nocase ascii wide
                        $string24_AutoSUID_greyware_tool_keyword = /emacs\s\-Q\s\-nw\s\-\-eval\s\'\(term\s\\\\"\/bin\/sh\s\-p\\\\"\)/
                        $string25_AutoSUID_greyware_tool_keyword = /\'exec\s\/bin\/sh\s\-p\s0\<\&1\'\s\>\>\s\\\$TF/
                        $string26_AutoSUID_greyware_tool_keyword = /find\s\.\s\-exec\s\/bin\/sh\s\-p\s\\\;\s\-quit/
                        $string27_AutoSUID_greyware_tool_keyword = /find\s\/\s\-xdev\s\-user\sroot\s\\\(\s\-perm\s\-4000\s\-o\s\-perm\s\-2000\s\-o\s\-perm\s\-6000\s\\\)\s2\>\/dev\/null/
                        $string28_AutoSUID_greyware_tool_keyword = /gdb\s\-nx\s\-ex\s\'python\simport\sos.{0,1000}os\.execl\(\\\\"\/bin\/sh\\/
                        $string29_AutoSUID_greyware_tool_keyword = "genie -c '/bin/sh'"
                        $string30_AutoSUID_greyware_tool_keyword = /gimp\s\-idf\s\-\-batch\-interpreter\=python\-fu\-eval\s\-b\s\'import\sos.{0,1000}\sos\.execl\(.{0,1000}\/bin\/sh/
                        $string31_AutoSUID_greyware_tool_keyword = "ionice /bin/sh -p"
                        $string32_AutoSUID_greyware_tool_keyword = "logsave /dev/null /bin/sh -i -p"
                        $string33_AutoSUID_greyware_tool_keyword = "msgfilter -P /bin/sh -p -c '/bin/sh"
                        $string34_AutoSUID_greyware_tool_keyword = /php\s\-r\s\\\\"pcntl_exec\(\'\/bin\/sh\'/
                        $string35_AutoSUID_greyware_tool_keyword = /rsync\s\-e\s\'sh\s\-p\s\-c\s.{0,1000}sh\s0\<\&2\s1\>\&2.{0,1000}127\.0\.0\.1\:\/dev\/null/ nocase ascii wide
                        $string36_AutoSUID_greyware_tool_keyword = "strace -o /dev/null /bin/sh -p"
                        $string37_AutoSUID_greyware_tool_keyword = "taskset 1 /bin/sh -p"
                        $string38_AutoSUID_greyware_tool_keyword = /vim\s\-c\s\'\:py3\simport\sos.{0,1000}\sos\.execl\(\\\\"\/bin\/sh\\/
                        $string39_AutoSUID_greyware_tool_keyword = /vimdiff\s\-c\s\'\:py3\simport\sos.{0,1000}\sos\.execl\(\\\\"\/bin\/sh\\/
                        $string40_AutoSUID_greyware_tool_keyword = "xargs -a /dev/null sh -p" nocase ascii wide

    condition:
        any of them
}