rule rule_reverse_shell_generator_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'reverse-shell-generator' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "reverse-shell-generator"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_reverse_shell_generator_offensive_tool_keyword = " perl-reverse-shell - " nocase ascii wide
                        $string2_reverse_shell_generator_offensive_tool_keyword = " reverse_shell_generator" nocase ascii wide
                        $string3_reverse_shell_generator_offensive_tool_keyword = " reverse_shell_generator" nocase ascii wide
                        $string4_reverse_shell_generator_offensive_tool_keyword = /\swindows\/shell\/bind_tcp\s.{0,100}shellcode/ nocase ascii wide
                        $string5_reverse_shell_generator_offensive_tool_keyword = /\\"\-c\s\\\\"sh\s\-i\s\>\&\s\/dev\/tcp\// nocase ascii wide
                        $string6_reverse_shell_generator_offensive_tool_keyword = /\.revshells\.com/ nocase ascii wide
                        $string7_reverse_shell_generator_offensive_tool_keyword = /\/ncat\s.{0,100}\s\-e\ssh/
                        $string8_reverse_shell_generator_offensive_tool_keyword = "/Reverse Shell Tab -->"
                        $string9_reverse_shell_generator_offensive_tool_keyword = /\/reverse\.exe/ nocase ascii wide
                        $string10_reverse_shell_generator_offensive_tool_keyword = "/reverse-shell-generator" nocase ascii wide
                        $string11_reverse_shell_generator_offensive_tool_keyword = /\/reverse\-shell\-generator\.git/ nocase ascii wide
                        $string12_reverse_shell_generator_offensive_tool_keyword = /\/revshells\.com/ nocase ascii wide
                        $string13_reverse_shell_generator_offensive_tool_keyword = /\\nc\.exe\s.{0,100}\s\-e\ssh/ nocase ascii wide
                        $string14_reverse_shell_generator_offensive_tool_keyword = /\\reverse\.exe/ nocase ascii wide
                        $string15_reverse_shell_generator_offensive_tool_keyword = ">JSP Backdoor Reverse Shell<" nocase ascii wide
                        $string16_reverse_shell_generator_offensive_tool_keyword = /0\<\&196\;exec\s196\<\>\/dev\/tcp\/.{0,100}\/.{0,100}\;\ssh\s\<\&196\s\>\&196\s2\>\&196/ nocase ascii wide
                        $string17_reverse_shell_generator_offensive_tool_keyword = "0dayCTF/reverse-shell-generator" nocase ascii wide
                        $string18_reverse_shell_generator_offensive_tool_keyword = "android/meterpreter/reverse_tcp" nocase ascii wide
                        $string19_reverse_shell_generator_offensive_tool_keyword = "apple_ios/aarch64/meterpreter_reverse_tcp" nocase ascii wide
                        $string20_reverse_shell_generator_offensive_tool_keyword = /awk\s\'BEGIN\s\{s\s\=\s\\"\/inet\/tcp\/0\/.{0,100}\\"\;.{0,100}printf\s\\"shell\>\\"\s\|\&\ss\;.{0,100}getline.{0,100}print\s\$0\s\|\&\ss\;.{0,100}close.{0,100}\}\'\s\/dev\/null/ nocase ascii wide
                        $string21_reverse_shell_generator_offensive_tool_keyword = /busybox\snc\s.{0,100}\s\-e\ssh/ nocase ascii wide
                        $string22_reverse_shell_generator_offensive_tool_keyword = "class ReverseBash"
                        $string23_reverse_shell_generator_offensive_tool_keyword = "cmd/unix/reverse_bash"
                        $string24_reverse_shell_generator_offensive_tool_keyword = "cmd/unix/reverse_python" nocase ascii wide
                        $string25_reverse_shell_generator_offensive_tool_keyword = /crystal\seval\s\'require\s\\"process\\"\;require\s\\"socket\\"\;.{0,100}Socket\.tcp.{0,100}connect.{0,100}Process\.new.{0,100}output\.gets_to_end/ nocase ascii wide
                        $string26_reverse_shell_generator_offensive_tool_keyword = "curl -Ns telnet://" nocase ascii wide
                        $string27_reverse_shell_generator_offensive_tool_keyword = /echo\s\'import\sos\'.{0,100}echo.{0,100}os\.system\(\\"nc\s\-e\ssh.{0,100}\'.{0,100}\s\>\s\/tmp\// nocase ascii wide
                        $string28_reverse_shell_generator_offensive_tool_keyword = /echo\s\'package\smain\;.{0,100}net\.Dial\(\\"tcp\\".{0,100}exec\.Command\(\\"\/bin\/bash\\"\).{0,100}cmd\.Stdin\=.{0,100}cmd\.Stdout\=.{0,100}cmd\.Stderr\=.{0,100}cmd\.Run\(\).{0,100}\'\s\>\s\/tmp\/.{0,100}\.go.{0,100}go\srun\s\/tmp\//
                        $string29_reverse_shell_generator_offensive_tool_keyword = /echo\s\'package\smain\;.{0,100}net\.Dial\(\\"tcp\\".{0,100}exec\.Command\(\\"\/bin\/sh\\"\).{0,100}cmd\.Stdin\=.{0,100}cmd\.Stdout\=.{0,100}cmd\.Stderr\=.{0,100}cmd\.Run\(\).{0,100}\'\s\>\s\/tmp\/.{0,100}\.go.{0,100}go\srun\s\/tmp\//
                        $string30_reverse_shell_generator_offensive_tool_keyword = /echo\s\'package\smain\;.{0,100}net\.Dial\(\\"tcp\\".{0,100}exec\.Command\(\\"bash\\"\).{0,100}cmd\.Stdin\=.{0,100}cmd\.Stdout\=.{0,100}cmd\.Stderr\=.{0,100}cmd\.Run\(\).{0,100}\'\s\>\s\/tmp\/.{0,100}\.go.{0,100}go\srun\s\/tmp\//
                        $string31_reverse_shell_generator_offensive_tool_keyword = /echo\s\'package\smain\;.{0,100}net\.Dial\(\\"tcp\\".{0,100}exec\.Command\(\\"cmd\\"\).{0,100}cmd\.Stdin\=.{0,100}cmd\.Stdout\=.{0,100}cmd\.Stderr\=.{0,100}cmd\.Run\(\).{0,100}\'\s\>\s\/tmp\/.{0,100}\.go.{0,100}go\srun\s\/tmp\// nocase ascii wide
                        $string32_reverse_shell_generator_offensive_tool_keyword = /echo\s\'package\smain\;.{0,100}net\.Dial\(\\"tcp\\".{0,100}exec\.Command\(\\"powershell\\"\).{0,100}cmd\.Stdin\=.{0,100}cmd\.Stdout\=.{0,100}cmd\.Stderr\=.{0,100}cmd\.Run\(\).{0,100}\'\s\>\s\/tmp\/.{0,100}\.go.{0,100}go\srun\s\/tmp\// nocase ascii wide
                        $string33_reverse_shell_generator_offensive_tool_keyword = /echo\s\'package\smain\;.{0,100}net\.Dial\(\\"tcp\\".{0,100}exec\.Command\(\\"pwsh\\"\).{0,100}cmd\.Stdin\=.{0,100}cmd\.Stdout\=.{0,100}cmd\.Stderr\=.{0,100}cmd\.Run\(\).{0,100}\'\s\>\s\/tmp\/.{0,100}\.go.{0,100}go\srun\s\/tmp\// nocase ascii wide
                        $string34_reverse_shell_generator_offensive_tool_keyword = /echo\s\'package\smain\;.{0,100}net\.Dial\(\\"tcp\\".{0,100}exec\.Command\(\\"sh\\"\).{0,100}cmd\.Stdin\=.{0,100}cmd\.Stdout\=.{0,100}cmd\.Stderr\=.{0,100}cmd\.Run\(\).{0,100}\'\s\>\s\/tmp\/.{0,100}\.go.{0,100}go\srun\s\/tmp\// nocase ascii wide
                        $string35_reverse_shell_generator_offensive_tool_keyword = /echo\s\'package\smain\;.{0,100}net\.Dial\(\\"tcp\\".{0,100}exec\.Command\(\\"zsh\\"\).{0,100}cmd\.Stdin\=.{0,100}cmd\.Stdout\=.{0,100}cmd\.Stderr\=.{0,100}cmd\.Run\(\).{0,100}\'\s\>\s\/tmp\/.{0,100}\.go.{0,100}go\srun\s\/tmp\// nocase ascii wide
                        $string36_reverse_shell_generator_offensive_tool_keyword = /exec\s5\<\>\/dev\/tcp\/.{0,100}\/.{0,100}\;cat\s\<\&5\s\|\swhile\sread\sline\;\sdo\s\$line\s2\>\&5\s\>\&5\;\sdone/ nocase ascii wide
                        $string37_reverse_shell_generator_offensive_tool_keyword = /export\sRHOST\=.{0,100}export\sRPORT\=.{0,100}python3\s\-c.{0,100}socket\.socket\(\).{0,100}connect.{0,100}os\.getenv\(\\"RHOST\\"\).{0,100}pty\.spawn\(\\"sh\\"\)/ nocase ascii wide
                        $string38_reverse_shell_generator_offensive_tool_keyword = /import\s\'dart\:io\'\;.{0,100}Socket\.connect\(.{0,100}\,\s.{0,100}Process\.start\(\'sh\'\,\s\[\]\).{0,100}socket\.write\(output\)\;/ nocase ascii wide
                        $string39_reverse_shell_generator_offensive_tool_keyword = "Invoke-ConPtyShell " nocase ascii wide
                        $string40_reverse_shell_generator_offensive_tool_keyword = /Invoke\-ConPtyShell\.ps1/ nocase ascii wide
                        $string41_reverse_shell_generator_offensive_tool_keyword = "JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQAwAC4AMQAwACIALAA5ADAAMAAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBu" nocase ascii wide
                        $string42_reverse_shell_generator_offensive_tool_keyword = "java/jsp_shell_reverse_tcp" nocase ascii wide
                        $string43_reverse_shell_generator_offensive_tool_keyword = "java/shell_reverse_tcp" nocase ascii wide
                        $string44_reverse_shell_generator_offensive_tool_keyword = "linux/x64/meterpreter/reverse_tcp"
                        $string45_reverse_shell_generator_offensive_tool_keyword = "linux/x64/shell_reverse_tcp"
                        $string46_reverse_shell_generator_offensive_tool_keyword = /lua\s\-e.{0,100}require\(\'socket\'\)\;.{0,100}t\:connect.{0,100}os\.execute\(\'\\"\/bin\/bash\\"\s\<\&3\s\>\&3\s2\>\&3\'\)\;/
                        $string47_reverse_shell_generator_offensive_tool_keyword = /lua\s\-e.{0,100}require\(\'socket\'\)\;.{0,100}t\:connect.{0,100}os\.execute\(\'\\"\/bin\/sh\\"\s\<\&3\s\>\&3\s2\>\&3\'\)\;/
                        $string48_reverse_shell_generator_offensive_tool_keyword = /lua\s\-e.{0,100}require\(\'socket\'\)\;.{0,100}t\:connect.{0,100}os\.execute\(\'\\"bash\\"\s\<\&3\s\>\&3\s2\>\&3\'\)\;/
                        $string49_reverse_shell_generator_offensive_tool_keyword = /lua\s\-e.{0,100}require\(\'socket\'\)\;.{0,100}t\:connect.{0,100}os\.execute\(\'\\"cmd\\"\s\<\&3\s\>\&3\s2\>\&3\'\)\;/ nocase ascii wide
                        $string50_reverse_shell_generator_offensive_tool_keyword = /lua\s\-e.{0,100}require\(\'socket\'\)\;.{0,100}t\:connect.{0,100}os\.execute\(\'\\"powershell\\"\s\<\&3\s\>\&3\s2\>\&3\'\)\;/ nocase ascii wide
                        $string51_reverse_shell_generator_offensive_tool_keyword = /lua\s\-e.{0,100}require\(\'socket\'\)\;.{0,100}t\:connect.{0,100}os\.execute\(\'\\"pwsh\\"\s\<\&3\s\>\&3\s2\>\&3\'\)\;/ nocase ascii wide
                        $string52_reverse_shell_generator_offensive_tool_keyword = /lua\s\-e.{0,100}require\(\'socket\'\)\;.{0,100}t\:connect.{0,100}os\.execute\(\'\\"zsh\\"\s\<\&3\s\>\&3\s2\>\&3\'\)\;/ nocase ascii wide
                        $string53_reverse_shell_generator_offensive_tool_keyword = /lua\s\-e.{0,100}require\(\'socket\'\)\;.{0,100}t\:connect.{0,100}os\.execute\(\'sh\s\-i\s\<\&3\s\>\&3\s2\>\&3\'\)\;/ nocase ascii wide
                        $string54_reverse_shell_generator_offensive_tool_keyword = /lua5\.1\s\-e.{0,100}require\(\\"socket\\"\).{0,100}tcp\:connect.{0,100}io\.popen.{0,100}receive\(\).{0,100}send\(\)/ nocase ascii wide
                        $string55_reverse_shell_generator_offensive_tool_keyword = "msfvenom -p " nocase ascii wide
                        $string56_reverse_shell_generator_offensive_tool_keyword = /Net\.Sockets\.TCPClient.{0,100}Net\.Security\.SslStream.{0,100}AuthenticateAsClient.{0,100}Invoke\-Expression.{0,100}Out\-String/ nocase ascii wide
                        $string57_reverse_shell_generator_offensive_tool_keyword = "Online - Reverse Shell Generator" nocase ascii wide
                        $string58_reverse_shell_generator_offensive_tool_keyword = "osx/x64/meterpreter/reverse_tcp" nocase ascii wide
                        $string59_reverse_shell_generator_offensive_tool_keyword = "osx/x64/meterpreter_reverse_tcp" nocase ascii wide
                        $string60_reverse_shell_generator_offensive_tool_keyword = "osx/x64/shell_reverse_tcp" nocase ascii wide
                        $string61_reverse_shell_generator_offensive_tool_keyword = "pentestmonkey/php-reverse-shell" nocase ascii wide
                        $string62_reverse_shell_generator_offensive_tool_keyword = /pentestmonkey\@pentestmonkey\.net/ nocase ascii wide
                        $string63_reverse_shell_generator_offensive_tool_keyword = /perl\s\-e\s\'use\sSocket\;\$.{0,100}\;socket\(S\,PF_INET\,SOCK_STREAM\,getprotobyname/ nocase ascii wide
                        $string64_reverse_shell_generator_offensive_tool_keyword = /perl\s\-MIO\s\-e\s.{0,100}new\sIO\:\:Socket\:\:INET\(PeerAddr\,\\".{0,100}\:.{0,100}\\"\)\;STDIN\-\>fdopen\(/ nocase ascii wide
                        $string65_reverse_shell_generator_offensive_tool_keyword = "PHP Meterpreter Stageless Reverse TCP" nocase ascii wide
                        $string66_reverse_shell_generator_offensive_tool_keyword = /php\s\-r\s\'\$s\=socket_create\(AF_INET\,SOCK_STREAM\,SOL_TCP\)\;socket_bind\(\$s/ nocase ascii wide
                        $string67_reverse_shell_generator_offensive_tool_keyword = /php\s\-r\s\'\$sock\=fsockopen\(.{0,100}\,.{0,100}\)\;exec\(\\"sh\s/ nocase ascii wide
                        $string68_reverse_shell_generator_offensive_tool_keyword = /php\s\-r\s\'\$sock\=fsockopen\(.{0,100}\,.{0,100}\)\;passthru\(\\"sh\s/ nocase ascii wide
                        $string69_reverse_shell_generator_offensive_tool_keyword = /php\s\-r\s\'\$sock\=fsockopen\(.{0,100}\,.{0,100}\)\;popen\(\\"sh\s/ nocase ascii wide
                        $string70_reverse_shell_generator_offensive_tool_keyword = /php\s\-r\s\'\$sock\=fsockopen\(.{0,100}\,.{0,100}\)\;shell_exec\(\\"sh\s/ nocase ascii wide
                        $string71_reverse_shell_generator_offensive_tool_keyword = /php\s\-r\s\'\$sock\=fsockopen\(.{0,100}\,.{0,100}\)\;system\(\\"sh\s/ nocase ascii wide
                        $string72_reverse_shell_generator_offensive_tool_keyword = /php\s\-r\s\'\$sock\=fsockopen\(.{0,100}\,.{0,100}proc_open\(\\"sh\\"\,/ nocase ascii wide
                        $string73_reverse_shell_generator_offensive_tool_keyword = "php/meterpreter_reverse_tcp" nocase ascii wide
                        $string74_reverse_shell_generator_offensive_tool_keyword = "php/reverse_php" nocase ascii wide
                        $string75_reverse_shell_generator_offensive_tool_keyword = /php\-reverse\-shell\.php/ nocase ascii wide
                        $string76_reverse_shell_generator_offensive_tool_keyword = /python\s\-c.{0,100}\'import\ssocket\,subprocess\,os\'.{0,100}socket\.socket\(socket\.AF_INET.{0,100}connect\(\(\\".{0,100}\)\).{0,100}dup2.{0,100}pty\.spawn\(\\"sh\\"\)\'/ nocase ascii wide
                        $string77_reverse_shell_generator_offensive_tool_keyword = /python\s\-c.{0,100}socket\.socket\(\).{0,100}connect.{0,100}dup2.{0,100}pty\.spawn\(\\"\/bin\/bash\\"\)/
                        $string78_reverse_shell_generator_offensive_tool_keyword = /python\s\-c.{0,100}socket\.socket\(\).{0,100}connect.{0,100}dup2.{0,100}pty\.spawn\(\\"\/bin\/sh\\"\)/
                        $string79_reverse_shell_generator_offensive_tool_keyword = /python\s\-c.{0,100}socket\.socket\(\).{0,100}connect.{0,100}dup2.{0,100}pty\.spawn\(\\"bash\\"\)/
                        $string80_reverse_shell_generator_offensive_tool_keyword = /python\s\-c.{0,100}socket\.socket\(\).{0,100}connect.{0,100}dup2.{0,100}pty\.spawn\(\\"cmd\\"\)/ nocase ascii wide
                        $string81_reverse_shell_generator_offensive_tool_keyword = /python\s\-c.{0,100}socket\.socket\(\).{0,100}connect.{0,100}dup2.{0,100}pty\.spawn\(\\"powershell\\"\)/ nocase ascii wide
                        $string82_reverse_shell_generator_offensive_tool_keyword = /python\s\-c.{0,100}socket\.socket\(\).{0,100}connect.{0,100}dup2.{0,100}pty\.spawn\(\\"pwsh\\"\)/ nocase ascii wide
                        $string83_reverse_shell_generator_offensive_tool_keyword = /python\s\-c.{0,100}socket\.socket\(\).{0,100}connect.{0,100}dup2.{0,100}pty\.spawn\(\\"sh\\"\)/ nocase ascii wide
                        $string84_reverse_shell_generator_offensive_tool_keyword = /python\s\-c.{0,100}socket\.socket\(\).{0,100}connect.{0,100}dup2.{0,100}pty\.spawn\(\\"zsh\\"\)/ nocase ascii wide
                        $string85_reverse_shell_generator_offensive_tool_keyword = /python.{0,100}\s\-c\s\'import\sos\,pty\,socket.{0,100}socket\.socket\(\).{0,100}s\.connect\(/ nocase ascii wide
                        $string86_reverse_shell_generator_offensive_tool_keyword = /python.{0,100}\s\-c\s\'import\ssocket\,subprocess\,os\;.{0,100}socket\.socket\(socket\.AF_INET\,socket\.SOCK_STREAM\).{0,100}\.connect\(/ nocase ascii wide
                        $string87_reverse_shell_generator_offensive_tool_keyword = "python3 -m pwncat -lp" nocase ascii wide
                        $string88_reverse_shell_generator_offensive_tool_keyword = "python3 -m pwncat -m windows -lp" nocase ascii wide
                        $string89_reverse_shell_generator_offensive_tool_keyword = "rcat connect -s sh " nocase ascii wide
                        $string90_reverse_shell_generator_offensive_tool_keyword = /require\(\'child_process\'\)\.exec\(\'nc\s\-e\s\\"\/bin\/bash\\"\s/
                        $string91_reverse_shell_generator_offensive_tool_keyword = /require\(\'child_process\'\)\.exec\(\'nc\s\-e\s\\"\/bin\/sh\\"\s/
                        $string92_reverse_shell_generator_offensive_tool_keyword = /require\(\'child_process\'\)\.exec\(\'nc\s\-e\s\\"bash\\"\s/
                        $string93_reverse_shell_generator_offensive_tool_keyword = /require\(\'child_process\'\)\.exec\(\'nc\s\-e\s\\"cmd\\"\s/ nocase ascii wide
                        $string94_reverse_shell_generator_offensive_tool_keyword = /require\(\'child_process\'\)\.exec\(\'nc\s\-e\s\\"powershell\\"\s/ nocase ascii wide
                        $string95_reverse_shell_generator_offensive_tool_keyword = /require\(\'child_process\'\)\.exec\(\'nc\s\-e\s\\"pwsh\\"\s/ nocase ascii wide
                        $string96_reverse_shell_generator_offensive_tool_keyword = /require\(\'child_process\'\)\.exec\(\'nc\s\-e\s\\"zsh\\"\s/ nocase ascii wide
                        $string97_reverse_shell_generator_offensive_tool_keyword = /require\(\'child_process\'\)\.exec\(\'nc\s\-e\ssh\s/ nocase ascii wide
                        $string98_reverse_shell_generator_offensive_tool_keyword = /revsockaddr\.sin_addr\.s_addr\s\=\sinet_addr\(/ nocase ascii wide
                        $string99_reverse_shell_generator_offensive_tool_keyword = /rm\s\/tmp\/f\;mkfifo\s\/tmp\/f\;cat\s\/tmp\/f\s\|\ssh\s\-i\s2\>\&1\s\|\snc\s/ nocase ascii wide
                        $string100_reverse_shell_generator_offensive_tool_keyword = /rm\s\/tmp\/f\;mkfifo\s\/tmp\/f\;cat\s\/tmp\/f\|sh\s\-i\s2\>\&1\|nc\s.{0,100}\s\>\/tmp\/f/ nocase ascii wide
                        $string101_reverse_shell_generator_offensive_tool_keyword = /rm\s\/tmp\/f\;mkfifo\s\/tmp\/f\;cat\s\/tmp\/f\|sh\s\-i\s2\>\&1\|ncat\s\-u\s.{0,100}\s\>\/tmp\// nocase ascii wide
                        $string102_reverse_shell_generator_offensive_tool_keyword = /ruby\s\-rsocket\s\-e.{0,100}TCPSocket\.new.{0,100}loop.{0,100}gets.{0,100}chomp.{0,100}IO\.popen.{0,100}read/ nocase ascii wide
                        $string103_reverse_shell_generator_offensive_tool_keyword = /ruby\s\-rsocket\s\-e\'spawn\(\\"\/bin\/bash\\"\,\[\:in\,\:out\,\:err\]\=\>TCPSocket\.new\(/
                        $string104_reverse_shell_generator_offensive_tool_keyword = /ruby\s\-rsocket\s\-e\'spawn\(\\"\/bin\/sh\\"\,\[\:in\,\:out\,\:err\]\=\>TCPSocket\.new\(/
                        $string105_reverse_shell_generator_offensive_tool_keyword = /ruby\s\-rsocket\s\-e\'spawn\(\\"bash\\"\,\[\:in\,\:out\,\:err\]\=\>TCPSocket\.new\(/
                        $string106_reverse_shell_generator_offensive_tool_keyword = /ruby\s\-rsocket\s\-e\'spawn\(\\"cmd\\"\,\[\:in\,\:out\,\:err\]\=\>TCPSocket\.new\(/ nocase ascii wide
                        $string107_reverse_shell_generator_offensive_tool_keyword = /ruby\s\-rsocket\s\-e\'spawn\(\\"powershell\\"\,\[\:in\,\:out\,\:err\]\=\>TCPSocket\.new\(/ nocase ascii wide
                        $string108_reverse_shell_generator_offensive_tool_keyword = /ruby\s\-rsocket\s\-e\'spawn\(\\"pwsh\\"\,\[\:in\,\:out\,\:err\]\=\>TCPSocket\.new\(/ nocase ascii wide
                        $string109_reverse_shell_generator_offensive_tool_keyword = /ruby\s\-rsocket\s\-e\'spawn\(\\"sh\\"\,\[\:in\,\:out\,\:err\]\=\>TCPSocket\.new\(/ nocase ascii wide
                        $string110_reverse_shell_generator_offensive_tool_keyword = /ruby\s\-rsocket\s\-e\'spawn\(\\"zsh\\"\,\[\:in\,\:out\,\:err\]\=\>TCPSocket\.new\(/ nocase ascii wide
                        $string111_reverse_shell_generator_offensive_tool_keyword = /Runtime\.getRuntime\(\)\.exec\(\\"bash\s\-c\s\/dev\/tcp\/.{0,100}\/.{0,100}\s\/bin\/bash\\"/
                        $string112_reverse_shell_generator_offensive_tool_keyword = /Runtime\.getRuntime\(\)\.exec\(\\"bash\s\-c\s\/dev\/tcp\/.{0,100}\/.{0,100}\s\/bin\/sh\\"/
                        $string113_reverse_shell_generator_offensive_tool_keyword = /Runtime\.getRuntime\(\)\.exec\(\\"bash\s\-c\s\/dev\/tcp\/.{0,100}\/.{0,100}\sbash\\"/
                        $string114_reverse_shell_generator_offensive_tool_keyword = /Runtime\.getRuntime\(\)\.exec\(\\"bash\s\-c\s\/dev\/tcp\/.{0,100}\/.{0,100}\scmd\\"/
                        $string115_reverse_shell_generator_offensive_tool_keyword = /Runtime\.getRuntime\(\)\.exec\(\\"bash\s\-c\s\/dev\/tcp\/.{0,100}\/.{0,100}\spowershell\\"/
                        $string116_reverse_shell_generator_offensive_tool_keyword = /Runtime\.getRuntime\(\)\.exec\(\\"bash\s\-c\s\/dev\/tcp\/.{0,100}\/.{0,100}\spwsh\\"/
                        $string117_reverse_shell_generator_offensive_tool_keyword = /Runtime\.getRuntime\(\)\.exec\(\\"bash\s\-c\s\/dev\/tcp\/.{0,100}\/.{0,100}\szsh\\"/
                        $string118_reverse_shell_generator_offensive_tool_keyword = /Runtime\.getRuntime\(\)\.exec\(\\"bash\s\-c.{0,100}\s\/dev\/tcp\/.{0,100}\//
                        $string119_reverse_shell_generator_offensive_tool_keyword = /sh\s\-i\s\>\&\s\/dev\/tcp\/.{0,100}\/.{0,100}\s0\>\&1/ nocase ascii wide
                        $string120_reverse_shell_generator_offensive_tool_keyword = /sh\s\-i\s\>\&\s\/dev\/udp\/.{0,100}\/.{0,100}\s0\>\&1/ nocase ascii wide
                        $string121_reverse_shell_generator_offensive_tool_keyword = /sh\s\-i\s5\<\>\s\/dev\/tcp\/.{0,100}\/.{0,100}\s0\<\&5\s1\>\&5\s2\>\&5/ nocase ascii wide
                        $string122_reverse_shell_generator_offensive_tool_keyword = /socat\sTCP\:.{0,100}\:.{0,100}\sEXEC\:\\"\/bin\/bash\\"/
                        $string123_reverse_shell_generator_offensive_tool_keyword = /socat\sTCP\:.{0,100}\:.{0,100}\sEXEC\:\\"\/bin\/sh\\"/
                        $string124_reverse_shell_generator_offensive_tool_keyword = /socat\sTCP\:.{0,100}\:.{0,100}\sEXEC\:\\"bash\\"/
                        $string125_reverse_shell_generator_offensive_tool_keyword = /socat\sTCP\:.{0,100}\:.{0,100}\sEXEC\:\\"cmd\\"/ nocase ascii wide
                        $string126_reverse_shell_generator_offensive_tool_keyword = /socat\sTCP\:.{0,100}\:.{0,100}\sEXEC\:\\"powershell\\"/ nocase ascii wide
                        $string127_reverse_shell_generator_offensive_tool_keyword = /socat\sTCP\:.{0,100}\:.{0,100}\sEXEC\:\\"pwsh\\"/ nocase ascii wide
                        $string128_reverse_shell_generator_offensive_tool_keyword = /socat\sTCP\:.{0,100}\:.{0,100}\sEXEC\:\\"zsh\\"/ nocase ascii wide
                        $string129_reverse_shell_generator_offensive_tool_keyword = /socat\sTCP\:.{0,100}\:.{0,100}\sEXEC\:sh/ nocase ascii wide
                        $string130_reverse_shell_generator_offensive_tool_keyword = /socat\sTCP\:.{0,100}\:.{0,100}\sEXEC\:\'sh/ nocase ascii wide
                        $string131_reverse_shell_generator_offensive_tool_keyword = /sqlite3.{0,100}\/dev\/null.{0,100}\'\.shell.{0,100}mkfifo.{0,100}\|\\"\/bin\/bash\\"\s\|\snc.{0,100}\'/
                        $string132_reverse_shell_generator_offensive_tool_keyword = /sqlite3.{0,100}\/dev\/null.{0,100}\'\.shell.{0,100}mkfifo.{0,100}\|\\"\/bin\/sh\\"\s\|\snc.{0,100}\'/
                        $string133_reverse_shell_generator_offensive_tool_keyword = /sqlite3.{0,100}\/dev\/null.{0,100}\'\.shell.{0,100}mkfifo.{0,100}\|\\"bash\\"\s\|\snc.{0,100}\'/
                        $string134_reverse_shell_generator_offensive_tool_keyword = /sqlite3.{0,100}\/dev\/null.{0,100}\'\.shell.{0,100}mkfifo.{0,100}\|\\"cmd\\"\s\|\snc.{0,100}\'/ nocase ascii wide
                        $string135_reverse_shell_generator_offensive_tool_keyword = /sqlite3.{0,100}\/dev\/null.{0,100}\'\.shell.{0,100}mkfifo.{0,100}\|\\"powershell\\"\s\|\snc.{0,100}\'/ nocase ascii wide
                        $string136_reverse_shell_generator_offensive_tool_keyword = /sqlite3.{0,100}\/dev\/null.{0,100}\'\.shell.{0,100}mkfifo.{0,100}\|\\"pwsh\\"\s\|\snc.{0,100}\'/ nocase ascii wide
                        $string137_reverse_shell_generator_offensive_tool_keyword = /sqlite3.{0,100}\/dev\/null.{0,100}\'\.shell.{0,100}mkfifo.{0,100}\|\\"zsh\\"\s\|\snc.{0,100}\'/ nocase ascii wide
                        $string138_reverse_shell_generator_offensive_tool_keyword = /sqlite3.{0,100}\/dev\/null.{0,100}\'\.shell.{0,100}mkfifo.{0,100}\|sh\s\-i.{0,100}\|nc.{0,100}\'/ nocase ascii wide
                        $string139_reverse_shell_generator_offensive_tool_keyword = "struct sockaddr_in revsockaddr" nocase ascii wide
                        $string140_reverse_shell_generator_offensive_tool_keyword = /stty\sraw\s\-echo\;\s\(stty\ssize\;\scat\)\s\|\snc\s\-lvnp/ nocase ascii wide
                        $string141_reverse_shell_generator_offensive_tool_keyword = /System\.Net\.Sockets\.TCPClient.{0,100}GetStream\(\).{0,100}iex.{0,100}Out\-String/ nocase ascii wide
                        $string142_reverse_shell_generator_offensive_tool_keyword = "Windows Bind TCP ShellCode - BOF" nocase ascii wide
                        $string143_reverse_shell_generator_offensive_tool_keyword = /Windows\sMeterpreter\sStaged\sReverse\sTCP\s\(x64/ nocase ascii wide
                        $string144_reverse_shell_generator_offensive_tool_keyword = /Windows\sMeterpreter\sStageless\sReverse\sTCP\s\(x64\)/ nocase ascii wide
                        $string145_reverse_shell_generator_offensive_tool_keyword = "Windows Staged JSP Reverse TCP" nocase ascii wide
                        $string146_reverse_shell_generator_offensive_tool_keyword = /Windows\sStaged\sReverse\sTCP\s\(x64\)/ nocase ascii wide
                        $string147_reverse_shell_generator_offensive_tool_keyword = /Windows\sStageless\sReverse\sTCP\s\(x64\)/ nocase ascii wide
                        $string148_reverse_shell_generator_offensive_tool_keyword = "windows/x64/meterpreter/reverse_tcp" nocase ascii wide
                        $string149_reverse_shell_generator_offensive_tool_keyword = "windows/x64/meterpreter_reverse_tcp" nocase ascii wide
                        $string150_reverse_shell_generator_offensive_tool_keyword = "windows/x64/meterpreter_reverse_tcp" nocase ascii wide
                        $string151_reverse_shell_generator_offensive_tool_keyword = "windows/x64/shell_reverse_tcp" nocase ascii wide
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
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}