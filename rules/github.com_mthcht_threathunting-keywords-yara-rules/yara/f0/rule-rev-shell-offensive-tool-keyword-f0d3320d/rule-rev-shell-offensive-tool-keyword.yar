rule rule_Rev_Shell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Rev-Shell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Rev-Shell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Rev_Shell_offensive_tool_keyword = /\srevshell\.py/ nocase ascii wide
                        $string2_Rev_Shell_offensive_tool_keyword = /\\"Generate\sreverse\sshell\spayloads\.\\"/ nocase ascii wide
                        $string3_Rev_Shell_offensive_tool_keyword = /\/Rev\-Shell\.git/ nocase ascii wide
                        $string4_Rev_Shell_offensive_tool_keyword = /\/revshell\.py/ nocase ascii wide
                        $string5_Rev_Shell_offensive_tool_keyword = /\\nGenerated\spayload\:/ nocase ascii wide
                        $string6_Rev_Shell_offensive_tool_keyword = /\\revshell\.py/ nocase ascii wide
                        $string7_Rev_Shell_offensive_tool_keyword = /\|\/bin\/sh\s\-i\s2\>\&1\|nc\s.{0,1000}\s\>\/tmp\/f/
                        $string8_Rev_Shell_offensive_tool_keyword = "a280f960cb4fc01ec2dbb4fe56f17122523878a9ece3713868244fbd95e7d7e6" nocase ascii wide
                        $string9_Rev_Shell_offensive_tool_keyword = /bash\s\-i\s\&\>\/dev\/tcp\/.{0,1000}\s\<\&1/
                        $string10_Rev_Shell_offensive_tool_keyword = /generate_payload\(language\,\sip\,\sport\)/ nocase ascii wide
                        $string11_Rev_Shell_offensive_tool_keyword = /nc\s\-e\s\/bin\/sh\s.{0,1000}\s/
                        $string12_Rev_Shell_offensive_tool_keyword = /powershell\s\-c\s.{0,1000}New\-Object\sSystem\.Net\.Sockets\.TCPClient\(\\".{0,1000}\$sendback\s\=\s\(iex\s.{0,1000}\$data.{0,1000}\s2\>\&1\s\|\sOut\-String/ nocase ascii wide
                        $string13_Rev_Shell_offensive_tool_keyword = /s\=socket\.socket\(socket\.AF_INET\,socket\.SOCK_STREAM\)\;s\.connect\(.{0,1000}os\.dup2\(s\.fileno.{0,1000}pty\.spawn\(\\"\/bin\/bash/
                        $string14_Rev_Shell_offensive_tool_keyword = /TF\=.{0,1000}mkfifo\s.{0,1000}\s\&\&\stelnet\s.{0,1000}\s0\<.{0,1000}\|\s\/bin\/sh\s1\>/
                        $string15_Rev_Shell_offensive_tool_keyword = "washingtonP1974/Rev-Shell" nocase ascii wide
                        $string16_Rev_Shell_offensive_tool_keyword = /www\.revshells\.com/ nocase ascii wide

    condition:
        any of them
}