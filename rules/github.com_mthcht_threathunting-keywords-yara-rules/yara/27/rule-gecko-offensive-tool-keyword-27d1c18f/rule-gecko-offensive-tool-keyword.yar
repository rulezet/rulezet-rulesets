rule rule_Gecko_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Gecko' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Gecko"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Gecko_offensive_tool_keyword = /\$\{\\"\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53\\"\}.{0,100}\$\{\\"\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53\\"\}.{0,100}\$\{\\"\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53\\"\}/ nocase ascii wide
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
                        $string14_Gecko_offensive_tool_keyword = /import\ssocket\,subprocess\,os\;s\=socket\.socket\(socket\.AF_INET\,socket\.SOCK_STREAM\)\;s\.connect\(.{0,100}subprocess\.call\(\[\\"\\"\/bin\/sh/
                        $string15_Gecko_offensive_tool_keyword = "MadExploits/Gecko" nocase ascii wide
                        $string16_Gecko_offensive_tool_keyword = /mkfifo\s\/tmp\/f\;cat\s\/tmp\/f\|\/bin\/sh\s\-i\s2\>\&1\|nc\s/
                        $string17_Gecko_offensive_tool_keyword = /pwnkit\s\\"id\\"\s\>\s\.mad\-root/ nocase ascii wide
                        $string18_Gecko_offensive_tool_keyword = "pwnkit \"useradd " nocase ascii wide
                        $string19_Gecko_offensive_tool_keyword = /wget\shttp.{0,100}\s\-O\spwnkit/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}