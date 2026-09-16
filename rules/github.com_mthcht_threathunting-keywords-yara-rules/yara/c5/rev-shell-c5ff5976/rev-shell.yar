rule Rev_Shell
{
    meta:
        description = "Detection patterns for the tool 'Rev-Shell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Rev-Shell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\srevshell\.py/ nocase ascii wide
                        $string2 = /\\"Generate\sreverse\sshell\spayloads\.\\"/ nocase ascii wide
                        $string3 = /\/Rev\-Shell\.git/ nocase ascii wide
                        $string4 = /\/revshell\.py/ nocase ascii wide
                        $string5 = /\\nGenerated\spayload\:/ nocase ascii wide
                        $string6 = /\\revshell\.py/ nocase ascii wide
                        $string7 = /\|\/bin\/sh\s\-i\s2\>\&1\|nc\s.{0,1000}\s\>\/tmp\/f/
                        $string8 = "a280f960cb4fc01ec2dbb4fe56f17122523878a9ece3713868244fbd95e7d7e6" nocase ascii wide
                        $string9 = /bash\s\-i\s\&\>\/dev\/tcp\/.{0,1000}\s\<\&1/
                        $string10 = /generate_payload\(language\,\sip\,\sport\)/ nocase ascii wide
                        $string11 = /nc\s\-e\s\/bin\/sh\s.{0,1000}\s/
                        $string12 = /powershell\s\-c\s.{0,1000}New\-Object\sSystem\.Net\.Sockets\.TCPClient\(\\".{0,1000}\$sendback\s\=\s\(iex\s.{0,1000}\$data.{0,1000}\s2\>\&1\s\|\sOut\-String/ nocase ascii wide
                        $string13 = /s\=socket\.socket\(socket\.AF_INET\,socket\.SOCK_STREAM\)\;s\.connect\(.{0,1000}os\.dup2\(s\.fileno.{0,1000}pty\.spawn\(\\"\/bin\/bash/
                        $string14 = /TF\=.{0,1000}mkfifo\s.{0,1000}\s\&\&\stelnet\s.{0,1000}\s0\<.{0,1000}\|\s\/bin\/sh\s1\>/
                        $string15 = "washingtonP1974/Rev-Shell" nocase ascii wide
                        $string16 = /www\.revshells\.com/ nocase ascii wide

    condition:
        any of them
}