rule rule_Gecko_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Gecko' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Gecko"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Gecko_offensive_tool_keyword = /\$\{\\"\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53\\"\}.{0,1000}\$\{\\"\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53\\"\}.{0,1000}\$\{\\"\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53\\"\}/ nocase ascii wide
                        $string2_Gecko_offensive_tool_keyword = /\$2y\$10\$ACTF7jbtyof6YoTCqitwLOxQ9II8xitPKC4pNi6SQjZM3HXkKiCZ/ nocase ascii wide
                        $string3_Gecko_offensive_tool_keyword = /\/gecko\-new\.php/ nocase ascii wide
                        $string4_Gecko_offensive_tool_keyword = /\/gecko\-old\.php/ nocase ascii wide
                        $string5_Gecko_offensive_tool_keyword = /\\gecko\-new\.php/ nocase ascii wide
                        $string6_Gecko_offensive_tool_keyword = /\\gecko\-old\.php/ nocase ascii wide
                        $string7_Gecko_offensive_tool_keyword = "21c9869676708d67b55fe9f17c7c43fadaf3a9b27bf013b9bb0ba673d70da013" nocase ascii wide
                        $string8_Gecko_offensive_tool_keyword = "618eea76cd6f9ea8adcaa2e96236c352db4a034e52bd3d1a1140012d5510389b" nocase ascii wide
                        $string9_Gecko_offensive_tool_keyword = "9f25da71d888618eb41ff007df64538c1f9a81a717701e66481ef9b14394e09d" nocase ascii wide
                        $string10_Gecko_offensive_tool_keyword = "a0bf933c2db4c92515bd4bcbfd5e7e07baca998423bdc11056f5271e3b93aef5" nocase ascii wide
                        $string11_Gecko_offensive_tool_keyword = /chmod\s\+x\spwnkit/
                        $string12_Gecko_offensive_tool_keyword = /https\:\/\/github\.com\/MadExploits\/Privelege\-escalation\/raw\/main\/pwnkit/ nocase ascii wide
                        $string13_Gecko_offensive_tool_keyword = /https\:\/\/phppasswordhash\.com\// nocase ascii wide
                        $string14_Gecko_offensive_tool_keyword = /import\ssocket\,subprocess\,os\;s\=socket\.socket\(socket\.AF_INET\,socket\.SOCK_STREAM\)\;s\.connect\(.{0,1000}subprocess\.call\(\[\\"\\"\/bin\/sh/
                        $string15_Gecko_offensive_tool_keyword = "MadExploits/Gecko" nocase ascii wide
                        $string16_Gecko_offensive_tool_keyword = /mkfifo\s\/tmp\/f\;cat\s\/tmp\/f\|\/bin\/sh\s\-i\s2\>\&1\|nc\s/
                        $string17_Gecko_offensive_tool_keyword = /pwnkit\s\\"id\\"\s\>\s\.mad\-root/ nocase ascii wide
                        $string18_Gecko_offensive_tool_keyword = "pwnkit \"useradd " nocase ascii wide
                        $string19_Gecko_offensive_tool_keyword = /wget\shttp.{0,1000}\s\-O\spwnkit/ nocase ascii wide

    condition:
        any of them
}