rule reverse_shell_generator
{
    meta:
        description = "Detection patterns for the tool 'reverse-shell-generator' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "reverse-shell-generator"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " perl-reverse-shell - " nocase ascii wide
                        $string2 = " reverse_shell_generator" nocase ascii wide
                        $string3 = " reverse_shell_generator" nocase ascii wide
                        $string4 = /\swindows\/shell\/bind_tcp\s.{0,1000}shellcode/ nocase ascii wide
                        $string5 = /\\"\-c\s\\\\"sh\s\-i\s\>\&\s\/dev\/tcp\// nocase ascii wide
                        $string6 = /\.revshells\.com/ nocase ascii wide
                        $string7 = /\/ncat\s.{0,1000}\s\-e\ssh/
                        $string8 = "/Reverse Shell Tab -->"
                        $string9 = /\/reverse\.exe/ nocase ascii wide
                        $string10 = "/reverse-shell-generator" nocase ascii wide
                        $string11 = /\/reverse\-shell\-generator\.git/ nocase ascii wide
                        $string12 = /\/revshells\.com/ nocase ascii wide
                        $string13 = /\\nc\.exe\s.{0,1000}\s\-e\ssh/ nocase ascii wide
                        $string14 = /\\reverse\.exe/ nocase ascii wide
                        $string15 = ">JSP Backdoor Reverse Shell<" nocase ascii wide
                        $string16 = /0\<\&196\;exec\s196\<\>\/dev\/tcp\/.{0,1000}\/.{0,1000}\;\ssh\s\<\&196\s\>\&196\s2\>\&196/ nocase ascii wide
                        $string17 = "0dayCTF/reverse-shell-generator" nocase ascii wide
                        $string18 = "android/meterpreter/reverse_tcp" nocase ascii wide
                        $string19 = "apple_ios/aarch64/meterpreter_reverse_tcp" nocase ascii wide
                        $string20 = /awk\s\'BEGIN\s\{s\s\=\s\\"\/inet\/tcp\/0\/.{0,1000}\\"\;.{0,1000}printf\s\\"shell\>\\"\s\|\&\ss\;.{0,1000}getline.{0,1000}print\s\$0\s\|\&\ss\;.{0,1000}close.{0,1000}\}\'\s\/dev\/null/ nocase ascii wide
                        $string21 = /busybox\snc\s.{0,1000}\s\-e\ssh/ nocase ascii wide
                        $string22 = "class ReverseBash"
                        $string23 = "cmd/unix/reverse_bash"
                        $string24 = "cmd/unix/reverse_python" nocase ascii wide
                        $string25 = /crystal\seval\s\'require\s\\"process\\"\;require\s\\"socket\\"\;.{0,1000}Socket\.tcp.{0,1000}connect.{0,1000}Process\.new.{0,1000}output\.gets_to_end/ nocase ascii wide
                        $string26 = "curl -Ns telnet://" nocase ascii wide
                        $string27 = /echo\s\'import\sos\'.{0,1000}echo.{0,1000}os\.system\(\\"nc\s\-e\ssh.{0,1000}\'.{0,1000}\s\>\s\/tmp\// nocase ascii wide
                        $string28 = /echo\s\'package\smain\;.{0,1000}net\.Dial\(\\"tcp\\".{0,1000}exec\.Command\(\\"\/bin\/bash\\"\).{0,1000}cmd\.Stdin\=.{0,1000}cmd\.Stdout\=.{0,1000}cmd\.Stderr\=.{0,1000}cmd\.Run\(\).{0,1000}\'\s\>\s\/tmp\/.{0,1000}\.go.{0,1000}go\srun\s\/tmp\//
                        $string29 = /echo\s\'package\smain\;.{0,1000}net\.Dial\(\\"tcp\\".{0,1000}exec\.Command\(\\"\/bin\/sh\\"\).{0,1000}cmd\.Stdin\=.{0,1000}cmd\.Stdout\=.{0,1000}cmd\.Stderr\=.{0,1000}cmd\.Run\(\).{0,1000}\'\s\>\s\/tmp\/.{0,1000}\.go.{0,1000}go\srun\s\/tmp\//
                        $string30 = /echo\s\'package\smain\;.{0,1000}net\.Dial\(\\"tcp\\".{0,1000}exec\.Command\(\\"bash\\"\).{0,1000}cmd\.Stdin\=.{0,1000}cmd\.Stdout\=.{0,1000}cmd\.Stderr\=.{0,1000}cmd\.Run\(\).{0,1000}\'\s\>\s\/tmp\/.{0,1000}\.go.{0,1000}go\srun\s\/tmp\//
                        $string31 = /echo\s\'package\smain\;.{0,1000}net\.Dial\(\\"tcp\\".{0,1000}exec\.Command\(\\"cmd\\"\).{0,1000}cmd\.Stdin\=.{0,1000}cmd\.Stdout\=.{0,1000}cmd\.Stderr\=.{0,1000}cmd\.Run\(\).{0,1000}\'\s\>\s\/tmp\/.{0,1000}\.go.{0,1000}go\srun\s\/tmp\// nocase ascii wide
                        $string32 = /echo\s\'package\smain\;.{0,1000}net\.Dial\(\\"tcp\\".{0,1000}exec\.Command\(\\"powershell\\"\).{0,1000}cmd\.Stdin\=.{0,1000}cmd\.Stdout\=.{0,1000}cmd\.Stderr\=.{0,1000}cmd\.Run\(\).{0,1000}\'\s\>\s\/tmp\/.{0,1000}\.go.{0,1000}go\srun\s\/tmp\// nocase ascii wide
                        $string33 = /echo\s\'package\smain\;.{0,1000}net\.Dial\(\\"tcp\\".{0,1000}exec\.Command\(\\"pwsh\\"\).{0,1000}cmd\.Stdin\=.{0,1000}cmd\.Stdout\=.{0,1000}cmd\.Stderr\=.{0,1000}cmd\.Run\(\).{0,1000}\'\s\>\s\/tmp\/.{0,1000}\.go.{0,1000}go\srun\s\/tmp\// nocase ascii wide
                        $string34 = /echo\s\'package\smain\;.{0,1000}net\.Dial\(\\"tcp\\".{0,1000}exec\.Command\(\\"sh\\"\).{0,1000}cmd\.Stdin\=.{0,1000}cmd\.Stdout\=.{0,1000}cmd\.Stderr\=.{0,1000}cmd\.Run\(\).{0,1000}\'\s\>\s\/tmp\/.{0,1000}\.go.{0,1000}go\srun\s\/tmp\// nocase ascii wide
                        $string35 = /echo\s\'package\smain\;.{0,1000}net\.Dial\(\\"tcp\\".{0,1000}exec\.Command\(\\"zsh\\"\).{0,1000}cmd\.Stdin\=.{0,1000}cmd\.Stdout\=.{0,1000}cmd\.Stderr\=.{0,1000}cmd\.Run\(\).{0,1000}\'\s\>\s\/tmp\/.{0,1000}\.go.{0,1000}go\srun\s\/tmp\// nocase ascii wide
                        $string36 = /exec\s5\<\>\/dev\/tcp\/.{0,1000}\/.{0,1000}\;cat\s\<\&5\s\|\swhile\sread\sline\;\sdo\s\$line\s2\>\&5\s\>\&5\;\sdone/ nocase ascii wide
                        $string37 = /export\sRHOST\=.{0,1000}export\sRPORT\=.{0,1000}python3\s\-c.{0,1000}socket\.socket\(\).{0,1000}connect.{0,1000}os\.getenv\(\\"RHOST\\"\).{0,1000}pty\.spawn\(\\"sh\\"\)/ nocase ascii wide
                        $string38 = /import\s\'dart\:io\'\;.{0,1000}Socket\.connect\(.{0,1000}\,\s.{0,1000}Process\.start\(\'sh\'\,\s\[\]\).{0,1000}socket\.write\(output\)\;/ nocase ascii wide
                        $string39 = "Invoke-ConPtyShell " nocase ascii wide
                        $string40 = /Invoke\-ConPtyShell\.ps1/ nocase ascii wide
                        $string41 = "JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQAwAC4AMQAwACIALAA5ADAAMAAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBu" nocase ascii wide
                        $string42 = "java/jsp_shell_reverse_tcp" nocase ascii wide
                        $string43 = "java/shell_reverse_tcp" nocase ascii wide
                        $string44 = "linux/x64/meterpreter/reverse_tcp"
                        $string45 = "linux/x64/shell_reverse_tcp"
                        $string46 = /lua\s\-e.{0,1000}require\(\'socket\'\)\;.{0,1000}t\:connect.{0,1000}os\.execute\(\'\\"\/bin\/bash\\"\s\<\&3\s\>\&3\s2\>\&3\'\)\;/
                        $string47 = /lua\s\-e.{0,1000}require\(\'socket\'\)\;.{0,1000}t\:connect.{0,1000}os\.execute\(\'\\"\/bin\/sh\\"\s\<\&3\s\>\&3\s2\>\&3\'\)\;/
                        $string48 = /lua\s\-e.{0,1000}require\(\'socket\'\)\;.{0,1000}t\:connect.{0,1000}os\.execute\(\'\\"bash\\"\s\<\&3\s\>\&3\s2\>\&3\'\)\;/
                        $string49 = /lua\s\-e.{0,1000}require\(\'socket\'\)\;.{0,1000}t\:connect.{0,1000}os\.execute\(\'\\"cmd\\"\s\<\&3\s\>\&3\s2\>\&3\'\)\;/ nocase ascii wide
                        $string50 = /lua\s\-e.{0,1000}require\(\'socket\'\)\;.{0,1000}t\:connect.{0,1000}os\.execute\(\'\\"powershell\\"\s\<\&3\s\>\&3\s2\>\&3\'\)\;/ nocase ascii wide
                        $string51 = /lua\s\-e.{0,1000}require\(\'socket\'\)\;.{0,1000}t\:connect.{0,1000}os\.execute\(\'\\"pwsh\\"\s\<\&3\s\>\&3\s2\>\&3\'\)\;/ nocase ascii wide
                        $string52 = /lua\s\-e.{0,1000}require\(\'socket\'\)\;.{0,1000}t\:connect.{0,1000}os\.execute\(\'\\"zsh\\"\s\<\&3\s\>\&3\s2\>\&3\'\)\;/ nocase ascii wide
                        $string53 = /lua\s\-e.{0,1000}require\(\'socket\'\)\;.{0,1000}t\:connect.{0,1000}os\.execute\(\'sh\s\-i\s\<\&3\s\>\&3\s2\>\&3\'\)\;/ nocase ascii wide
                        $string54 = /lua5\.1\s\-e.{0,1000}require\(\\"socket\\"\).{0,1000}tcp\:connect.{0,1000}io\.popen.{0,1000}receive\(\).{0,1000}send\(\)/ nocase ascii wide
                        $string55 = "msfvenom -p " nocase ascii wide
                        $string56 = /Net\.Sockets\.TCPClient.{0,1000}Net\.Security\.SslStream.{0,1000}AuthenticateAsClient.{0,1000}Invoke\-Expression.{0,1000}Out\-String/ nocase ascii wide
                        $string57 = "Online - Reverse Shell Generator" nocase ascii wide
                        $string58 = "osx/x64/meterpreter/reverse_tcp" nocase ascii wide
                        $string59 = "osx/x64/meterpreter_reverse_tcp" nocase ascii wide
                        $string60 = "osx/x64/shell_reverse_tcp" nocase ascii wide
                        $string61 = "pentestmonkey/php-reverse-shell" nocase ascii wide
                        $string62 = /pentestmonkey\@pentestmonkey\.net/ nocase ascii wide
                        $string63 = /perl\s\-e\s\'use\sSocket\;\$.{0,1000}\;socket\(S\,PF_INET\,SOCK_STREAM\,getprotobyname/ nocase ascii wide
                        $string64 = /perl\s\-MIO\s\-e\s.{0,1000}new\sIO\:\:Socket\:\:INET\(PeerAddr\,\\".{0,1000}\:.{0,1000}\\"\)\;STDIN\-\>fdopen\(/ nocase ascii wide
                        $string65 = "PHP Meterpreter Stageless Reverse TCP" nocase ascii wide
                        $string66 = /php\s\-r\s\'\$s\=socket_create\(AF_INET\,SOCK_STREAM\,SOL_TCP\)\;socket_bind\(\$s/ nocase ascii wide
                        $string67 = /php\s\-r\s\'\$sock\=fsockopen\(.{0,1000}\,.{0,1000}\)\;exec\(\\"sh\s/ nocase ascii wide
                        $string68 = /php\s\-r\s\'\$sock\=fsockopen\(.{0,1000}\,.{0,1000}\)\;passthru\(\\"sh\s/ nocase ascii wide
                        $string69 = /php\s\-r\s\'\$sock\=fsockopen\(.{0,1000}\,.{0,1000}\)\;popen\(\\"sh\s/ nocase ascii wide
                        $string70 = /php\s\-r\s\'\$sock\=fsockopen\(.{0,1000}\,.{0,1000}\)\;shell_exec\(\\"sh\s/ nocase ascii wide
                        $string71 = /php\s\-r\s\'\$sock\=fsockopen\(.{0,1000}\,.{0,1000}\)\;system\(\\"sh\s/ nocase ascii wide
                        $string72 = /php\s\-r\s\'\$sock\=fsockopen\(.{0,1000}\,.{0,1000}proc_open\(\\"sh\\"\,/ nocase ascii wide
                        $string73 = "php/meterpreter_reverse_tcp" nocase ascii wide
                        $string74 = "php/reverse_php" nocase ascii wide
                        $string75 = /php\-reverse\-shell\.php/ nocase ascii wide
                        $string76 = /python\s\-c.{0,1000}\'import\ssocket\,subprocess\,os\'.{0,1000}socket\.socket\(socket\.AF_INET.{0,1000}connect\(\(\\".{0,1000}\)\).{0,1000}dup2.{0,1000}pty\.spawn\(\\"sh\\"\)\'/ nocase ascii wide
                        $string77 = /python\s\-c.{0,1000}socket\.socket\(\).{0,1000}connect.{0,1000}dup2.{0,1000}pty\.spawn\(\\"\/bin\/bash\\"\)/
                        $string78 = /python\s\-c.{0,1000}socket\.socket\(\).{0,1000}connect.{0,1000}dup2.{0,1000}pty\.spawn\(\\"\/bin\/sh\\"\)/
                        $string79 = /python\s\-c.{0,1000}socket\.socket\(\).{0,1000}connect.{0,1000}dup2.{0,1000}pty\.spawn\(\\"bash\\"\)/
                        $string80 = /python\s\-c.{0,1000}socket\.socket\(\).{0,1000}connect.{0,1000}dup2.{0,1000}pty\.spawn\(\\"cmd\\"\)/ nocase ascii wide
                        $string81 = /python\s\-c.{0,1000}socket\.socket\(\).{0,1000}connect.{0,1000}dup2.{0,1000}pty\.spawn\(\\"powershell\\"\)/ nocase ascii wide
                        $string82 = /python\s\-c.{0,1000}socket\.socket\(\).{0,1000}connect.{0,1000}dup2.{0,1000}pty\.spawn\(\\"pwsh\\"\)/ nocase ascii wide
                        $string83 = /python\s\-c.{0,1000}socket\.socket\(\).{0,1000}connect.{0,1000}dup2.{0,1000}pty\.spawn\(\\"sh\\"\)/ nocase ascii wide
                        $string84 = /python\s\-c.{0,1000}socket\.socket\(\).{0,1000}connect.{0,1000}dup2.{0,1000}pty\.spawn\(\\"zsh\\"\)/ nocase ascii wide
                        $string85 = /python.{0,1000}\s\-c\s\'import\sos\,pty\,socket.{0,1000}socket\.socket\(\).{0,1000}s\.connect\(/ nocase ascii wide
                        $string86 = /python.{0,1000}\s\-c\s\'import\ssocket\,subprocess\,os\;.{0,1000}socket\.socket\(socket\.AF_INET\,socket\.SOCK_STREAM\).{0,1000}\.connect\(/ nocase ascii wide
                        $string87 = "python3 -m pwncat -lp" nocase ascii wide
                        $string88 = "python3 -m pwncat -m windows -lp" nocase ascii wide
                        $string89 = "rcat connect -s sh " nocase ascii wide
                        $string90 = /require\(\'child_process\'\)\.exec\(\'nc\s\-e\s\\"\/bin\/bash\\"\s/
                        $string91 = /require\(\'child_process\'\)\.exec\(\'nc\s\-e\s\\"\/bin\/sh\\"\s/
                        $string92 = /require\(\'child_process\'\)\.exec\(\'nc\s\-e\s\\"bash\\"\s/
                        $string93 = /require\(\'child_process\'\)\.exec\(\'nc\s\-e\s\\"cmd\\"\s/ nocase ascii wide
                        $string94 = /require\(\'child_process\'\)\.exec\(\'nc\s\-e\s\\"powershell\\"\s/ nocase ascii wide
                        $string95 = /require\(\'child_process\'\)\.exec\(\'nc\s\-e\s\\"pwsh\\"\s/ nocase ascii wide
                        $string96 = /require\(\'child_process\'\)\.exec\(\'nc\s\-e\s\\"zsh\\"\s/ nocase ascii wide
                        $string97 = /require\(\'child_process\'\)\.exec\(\'nc\s\-e\ssh\s/ nocase ascii wide
                        $string98 = /revsockaddr\.sin_addr\.s_addr\s\=\sinet_addr\(/ nocase ascii wide
                        $string99 = /rm\s\/tmp\/f\;mkfifo\s\/tmp\/f\;cat\s\/tmp\/f\s\|\ssh\s\-i\s2\>\&1\s\|\snc\s/ nocase ascii wide
                        $string100 = /rm\s\/tmp\/f\;mkfifo\s\/tmp\/f\;cat\s\/tmp\/f\|sh\s\-i\s2\>\&1\|nc\s.{0,1000}\s\>\/tmp\/f/ nocase ascii wide
                        $string101 = /rm\s\/tmp\/f\;mkfifo\s\/tmp\/f\;cat\s\/tmp\/f\|sh\s\-i\s2\>\&1\|ncat\s\-u\s.{0,1000}\s\>\/tmp\// nocase ascii wide
                        $string102 = /ruby\s\-rsocket\s\-e.{0,1000}TCPSocket\.new.{0,1000}loop.{0,1000}gets.{0,1000}chomp.{0,1000}IO\.popen.{0,1000}read/ nocase ascii wide
                        $string103 = /ruby\s\-rsocket\s\-e\'spawn\(\\"\/bin\/bash\\"\,\[\:in\,\:out\,\:err\]\=\>TCPSocket\.new\(/
                        $string104 = /ruby\s\-rsocket\s\-e\'spawn\(\\"\/bin\/sh\\"\,\[\:in\,\:out\,\:err\]\=\>TCPSocket\.new\(/
                        $string105 = /ruby\s\-rsocket\s\-e\'spawn\(\\"bash\\"\,\[\:in\,\:out\,\:err\]\=\>TCPSocket\.new\(/
                        $string106 = /ruby\s\-rsocket\s\-e\'spawn\(\\"cmd\\"\,\[\:in\,\:out\,\:err\]\=\>TCPSocket\.new\(/ nocase ascii wide
                        $string107 = /ruby\s\-rsocket\s\-e\'spawn\(\\"powershell\\"\,\[\:in\,\:out\,\:err\]\=\>TCPSocket\.new\(/ nocase ascii wide
                        $string108 = /ruby\s\-rsocket\s\-e\'spawn\(\\"pwsh\\"\,\[\:in\,\:out\,\:err\]\=\>TCPSocket\.new\(/ nocase ascii wide
                        $string109 = /ruby\s\-rsocket\s\-e\'spawn\(\\"sh\\"\,\[\:in\,\:out\,\:err\]\=\>TCPSocket\.new\(/ nocase ascii wide
                        $string110 = /ruby\s\-rsocket\s\-e\'spawn\(\\"zsh\\"\,\[\:in\,\:out\,\:err\]\=\>TCPSocket\.new\(/ nocase ascii wide
                        $string111 = /Runtime\.getRuntime\(\)\.exec\(\\"bash\s\-c\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\s\/bin\/bash\\"/
                        $string112 = /Runtime\.getRuntime\(\)\.exec\(\\"bash\s\-c\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\s\/bin\/sh\\"/
                        $string113 = /Runtime\.getRuntime\(\)\.exec\(\\"bash\s\-c\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\sbash\\"/
                        $string114 = /Runtime\.getRuntime\(\)\.exec\(\\"bash\s\-c\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\scmd\\"/
                        $string115 = /Runtime\.getRuntime\(\)\.exec\(\\"bash\s\-c\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\spowershell\\"/
                        $string116 = /Runtime\.getRuntime\(\)\.exec\(\\"bash\s\-c\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\spwsh\\"/
                        $string117 = /Runtime\.getRuntime\(\)\.exec\(\\"bash\s\-c\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\szsh\\"/
                        $string118 = /Runtime\.getRuntime\(\)\.exec\(\\"bash\s\-c.{0,1000}\s\/dev\/tcp\/.{0,1000}\//
                        $string119 = /sh\s\-i\s\>\&\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\s0\>\&1/ nocase ascii wide
                        $string120 = /sh\s\-i\s\>\&\s\/dev\/udp\/.{0,1000}\/.{0,1000}\s0\>\&1/ nocase ascii wide
                        $string121 = /sh\s\-i\s5\<\>\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\s0\<\&5\s1\>\&5\s2\>\&5/ nocase ascii wide
                        $string122 = /socat\sTCP\:.{0,1000}\:.{0,1000}\sEXEC\:\\"\/bin\/bash\\"/
                        $string123 = /socat\sTCP\:.{0,1000}\:.{0,1000}\sEXEC\:\\"\/bin\/sh\\"/
                        $string124 = /socat\sTCP\:.{0,1000}\:.{0,1000}\sEXEC\:\\"bash\\"/
                        $string125 = /socat\sTCP\:.{0,1000}\:.{0,1000}\sEXEC\:\\"cmd\\"/ nocase ascii wide
                        $string126 = /socat\sTCP\:.{0,1000}\:.{0,1000}\sEXEC\:\\"powershell\\"/ nocase ascii wide
                        $string127 = /socat\sTCP\:.{0,1000}\:.{0,1000}\sEXEC\:\\"pwsh\\"/ nocase ascii wide
                        $string128 = /socat\sTCP\:.{0,1000}\:.{0,1000}\sEXEC\:\\"zsh\\"/ nocase ascii wide
                        $string129 = /socat\sTCP\:.{0,1000}\:.{0,1000}\sEXEC\:sh/ nocase ascii wide
                        $string130 = /socat\sTCP\:.{0,1000}\:.{0,1000}\sEXEC\:\'sh/ nocase ascii wide
                        $string131 = /sqlite3.{0,1000}\/dev\/null.{0,1000}\'\.shell.{0,1000}mkfifo.{0,1000}\|\\"\/bin\/bash\\"\s\|\snc.{0,1000}\'/
                        $string132 = /sqlite3.{0,1000}\/dev\/null.{0,1000}\'\.shell.{0,1000}mkfifo.{0,1000}\|\\"\/bin\/sh\\"\s\|\snc.{0,1000}\'/
                        $string133 = /sqlite3.{0,1000}\/dev\/null.{0,1000}\'\.shell.{0,1000}mkfifo.{0,1000}\|\\"bash\\"\s\|\snc.{0,1000}\'/
                        $string134 = /sqlite3.{0,1000}\/dev\/null.{0,1000}\'\.shell.{0,1000}mkfifo.{0,1000}\|\\"cmd\\"\s\|\snc.{0,1000}\'/ nocase ascii wide
                        $string135 = /sqlite3.{0,1000}\/dev\/null.{0,1000}\'\.shell.{0,1000}mkfifo.{0,1000}\|\\"powershell\\"\s\|\snc.{0,1000}\'/ nocase ascii wide
                        $string136 = /sqlite3.{0,1000}\/dev\/null.{0,1000}\'\.shell.{0,1000}mkfifo.{0,1000}\|\\"pwsh\\"\s\|\snc.{0,1000}\'/ nocase ascii wide
                        $string137 = /sqlite3.{0,1000}\/dev\/null.{0,1000}\'\.shell.{0,1000}mkfifo.{0,1000}\|\\"zsh\\"\s\|\snc.{0,1000}\'/ nocase ascii wide
                        $string138 = /sqlite3.{0,1000}\/dev\/null.{0,1000}\'\.shell.{0,1000}mkfifo.{0,1000}\|sh\s\-i.{0,1000}\|nc.{0,1000}\'/ nocase ascii wide
                        $string139 = "struct sockaddr_in revsockaddr" nocase ascii wide
                        $string140 = /stty\sraw\s\-echo\;\s\(stty\ssize\;\scat\)\s\|\snc\s\-lvnp/ nocase ascii wide
                        $string141 = /System\.Net\.Sockets\.TCPClient.{0,1000}GetStream\(\).{0,1000}iex.{0,1000}Out\-String/ nocase ascii wide
                        $string142 = "Windows Bind TCP ShellCode - BOF" nocase ascii wide
                        $string143 = /Windows\sMeterpreter\sStaged\sReverse\sTCP\s\(x64/ nocase ascii wide
                        $string144 = /Windows\sMeterpreter\sStageless\sReverse\sTCP\s\(x64\)/ nocase ascii wide
                        $string145 = "Windows Staged JSP Reverse TCP" nocase ascii wide
                        $string146 = /Windows\sStaged\sReverse\sTCP\s\(x64\)/ nocase ascii wide
                        $string147 = /Windows\sStageless\sReverse\sTCP\s\(x64\)/ nocase ascii wide
                        $string148 = "windows/x64/meterpreter/reverse_tcp" nocase ascii wide
                        $string149 = "windows/x64/meterpreter_reverse_tcp" nocase ascii wide
                        $string150 = "windows/x64/meterpreter_reverse_tcp" nocase ascii wide
                        $string151 = "windows/x64/shell_reverse_tcp" nocase ascii wide

    condition:
        any of them
}