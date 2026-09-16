rule Gecko
{
    meta:
        description = "Detection patterns for the tool 'Gecko' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Gecko"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\$\{\\"\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53\\"\}.{0,1000}\$\{\\"\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53\\"\}.{0,1000}\$\{\\"\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53\\"\}/ nocase ascii wide
                        $string2 = /\$2y\$10\$ACTF7jbtyof6YoTCqitwLOxQ9II8xitPKC4pNi6SQjZM3HXkKiCZ/ nocase ascii wide
                        $string3 = /\/gecko\-new\.php/ nocase ascii wide
                        $string4 = /\/gecko\-old\.php/ nocase ascii wide
                        $string5 = /\\gecko\-new\.php/ nocase ascii wide
                        $string6 = /\\gecko\-old\.php/ nocase ascii wide
                        $string7 = "21c9869676708d67b55fe9f17c7c43fadaf3a9b27bf013b9bb0ba673d70da013" nocase ascii wide
                        $string8 = "618eea76cd6f9ea8adcaa2e96236c352db4a034e52bd3d1a1140012d5510389b" nocase ascii wide
                        $string9 = "9f25da71d888618eb41ff007df64538c1f9a81a717701e66481ef9b14394e09d" nocase ascii wide
                        $string10 = "a0bf933c2db4c92515bd4bcbfd5e7e07baca998423bdc11056f5271e3b93aef5" nocase ascii wide
                        $string11 = /chmod\s\+x\spwnkit/
                        $string12 = /https\:\/\/github\.com\/MadExploits\/Privelege\-escalation\/raw\/main\/pwnkit/ nocase ascii wide
                        $string13 = /https\:\/\/phppasswordhash\.com\// nocase ascii wide
                        $string14 = /import\ssocket\,subprocess\,os\;s\=socket\.socket\(socket\.AF_INET\,socket\.SOCK_STREAM\)\;s\.connect\(.{0,1000}subprocess\.call\(\[\\"\\"\/bin\/sh/
                        $string15 = "MadExploits/Gecko" nocase ascii wide
                        $string16 = /mkfifo\s\/tmp\/f\;cat\s\/tmp\/f\|\/bin\/sh\s\-i\s2\>\&1\|nc\s/
                        $string17 = /pwnkit\s\\"id\\"\s\>\s\.mad\-root/ nocase ascii wide
                        $string18 = "pwnkit \"useradd " nocase ascii wide
                        $string19 = /wget\shttp.{0,1000}\s\-O\spwnkit/ nocase ascii wide

    condition:
        any of them
}