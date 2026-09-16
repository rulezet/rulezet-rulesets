rule AutoSUID
{
    meta:
        description = "Detection patterns for the tool 'AutoSUID' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AutoSUID"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\spwn_tclsh\.me/ nocase ascii wide
                        $string2 = /\sWe\shave\sfound\sat\sleast\s.{0,1000}\spotential\sSUID\sexploitable\sfile\(s\)/ nocase ascii wide
                        $string3 = /\.\/capsh\s\-\-gid\=0\s\-\-uid\=0\s\-\-/
                        $string4 = /\.\/chroot\s\/\s\/bin\/sh\s\-p/
                        $string5 = /\.\/env\s\/bin\/sh\s\-p/
                        $string6 = /\.\/expect\s\-c\s\'spawn\s\/bin\/sh\s\-p\;interact\'/
                        $string7 = /\.\/flock\s\-u\s\/\s\/bin\/sh\s\-p/
                        $string8 = /\.\/nice\s\/bin\/sh\s\-p/
                        $string9 = /\.\/rview\s\-c\s\'\:py3\simport\sos.{0,1000}os\.execl\(\\\\"\/bin\/sh\\/
                        $string10 = /\/ld\.so\s\/bin\/sh\s\-p/
                        $string11 = "/perf stat /bin/sh -p"
                        $string12 = /\/perl\s\-e\s\'exec\s\\\\"\/bin\/sh\\\\"/
                        $string13 = /\/pwn_tclsh\.me/
                        $string14 = /\/rvim\s\-c\s\'\:py3\simport\sos.{0,1000}os\.execl\(\\\\"\/bin\/sh\\/
                        $string15 = "/sshpass /bin/sh -p"
                        $string16 = "/stdbuf -i0 /bin/sh -p"
                        $string17 = "/unshare -r /bin/sh"
                        $string18 = /\/view\s\-c\s\'\:py3\simport\sos.{0,1000}os\.execl\(\\\\"\/bin\/sh\\/
                        $string19 = /\/watch\s\-x\ssh\s\-c\s\'reset.{0,1000}\sexec\ssh\s1\>\&0\s2\>\&0/
                        $string20 = "agetty -o -p -l /bin/sh -a root tty"
                        $string21 = "cpulimit -l 100 -f -- /bin/sh -p"
                        $string22 = /dmsetup\screate\sbase\s\<\<EOF.{0,1000}0\s3534848\slinear\s\/dev\/loop0\s94208.{0,1000}\sEOF.{0,1000}\.\/dmsetup\sls\s\-\-exec\s\'\/bin\/sh\s\-p\s\-s/
                        $string23 = "docker run -v /:/mnt --rm -it alpine chroot /mnt sh" nocase ascii wide
                        $string24 = /emacs\s\-Q\s\-nw\s\-\-eval\s\'\(term\s\\\\"\/bin\/sh\s\-p\\\\"\)/
                        $string25 = /\'exec\s\/bin\/sh\s\-p\s0\<\&1\'\s\>\>\s\\\$TF/
                        $string26 = /find\s\.\s\-exec\s\/bin\/sh\s\-p\s\\\;\s\-quit/
                        $string27 = /find\s\/\s\-xdev\s\-user\sroot\s\\\(\s\-perm\s\-4000\s\-o\s\-perm\s\-2000\s\-o\s\-perm\s\-6000\s\\\)\s2\>\/dev\/null/
                        $string28 = /gdb\s\-nx\s\-ex\s\'python\simport\sos.{0,1000}os\.execl\(\\\\"\/bin\/sh\\/
                        $string29 = "genie -c '/bin/sh'"
                        $string30 = /gimp\s\-idf\s\-\-batch\-interpreter\=python\-fu\-eval\s\-b\s\'import\sos.{0,1000}\sos\.execl\(.{0,1000}\/bin\/sh/
                        $string31 = "ionice /bin/sh -p"
                        $string32 = "logsave /dev/null /bin/sh -i -p"
                        $string33 = "msgfilter -P /bin/sh -p -c '/bin/sh"
                        $string34 = /php\s\-r\s\\\\"pcntl_exec\(\'\/bin\/sh\'/
                        $string35 = /rsync\s\-e\s\'sh\s\-p\s\-c\s.{0,1000}sh\s0\<\&2\s1\>\&2.{0,1000}127\.0\.0\.1\:\/dev\/null/ nocase ascii wide
                        $string36 = "strace -o /dev/null /bin/sh -p"
                        $string37 = "taskset 1 /bin/sh -p"
                        $string38 = /vim\s\-c\s\'\:py3\simport\sos.{0,1000}\sos\.execl\(\\\\"\/bin\/sh\\/
                        $string39 = /vimdiff\s\-c\s\'\:py3\simport\sos.{0,1000}\sos\.execl\(\\\\"\/bin\/sh\\/
                        $string40 = "xargs -a /dev/null sh -p" nocase ascii wide

    condition:
        any of them
}