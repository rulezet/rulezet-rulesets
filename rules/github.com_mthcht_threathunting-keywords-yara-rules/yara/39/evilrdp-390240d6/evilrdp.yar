rule evilrdp
{
    meta:
        description = "Detection patterns for the tool 'evilrdp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "evilrdp"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sevilrdp\.gui\s/ nocase ascii wide
                        $string2 = /\/evilrdp\.git/ nocase ascii wide
                        $string3 = "/evilrdp/" nocase ascii wide
                        $string4 = /\\evilrdp\\/ nocase ascii wide
                        $string5 = /aardwolf\.extensions\.RDPEDYC\.vchannels\.socksoverrdp\simport\sSocksOverRDPChannel/ nocase ascii wide
                        $string6 = /aiocmd\\nested_completer\.py/ nocase ascii wide
                        $string7 = /Async\sRDP\sClient\.\sDuckyscript\swill\sbe\sexecuted\sby\spressing\sESC\s3\stimes/ nocase ascii wide
                        $string8 = /do_socksoverrdp\(.{0,1000}127\.0\.0\.1/ nocase ascii wide
                        $string9 = /do_socksproxy\(.{0,1000}\slisten_ip\s\=\s\'127\.0\.0\.1\'/ nocase ascii wide
                        $string10 = /do_startpscmd\(.{0,1000}serverscript\.ps1/ nocase ascii wide
                        $string11 = /ducky_keyboard_sender\(scancode/ nocase ascii wide
                        $string12 = "Emulates a rightclick on the given coordinates" nocase ascii wide
                        $string13 = /evilrdp\.exe/ nocase ascii wide
                        $string14 = "evilrdp-main" nocase ascii wide
                        $string15 = /Executes\sa\spowershell\scommand\son\sthe\sremote\shost\.\sRequires\sPSCMD/ nocase ascii wide
                        $string16 = /from\sevilrdp\.consolehelper/ nocase ascii wide
                        $string17 = "import EVILRDPConsole" nocase ascii wide
                        $string18 = "import EvilRDPGUI" nocase ascii wide
                        $string19 = /PSCMD\schannel\swas\seither\snot\sdefined\swhile\sconnecting\sOR\sthe\schannel\sname\sis\snot\sthe\sdefault\./ nocase ascii wide
                        $string20 = /pscmd\/serverscript\.ps1/ nocase ascii wide
                        $string21 = /pscmd\\serverscript\.ps1/ nocase ascii wide
                        $string22 = /rdp\+kerberos\-password\:\/\/.{0,1000}\?dc\=.{0,1000}proxytype.{0,1000}proxyhost/ nocase ascii wide
                        $string23 = /rdp\+ntlm\-password\:\/\/.{0,1000}\@/ nocase ascii wide
                        $string24 = /sendcmd\(.{0,1000}cmd\:PSCMDMessage/ nocase ascii wide
                        $string25 = "Set the correct channel name using \"\"pscmdchannel\"\" command" nocase ascii wide
                        $string26 = "skelsec/evilrdp" nocase ascii wide
                        $string27 = "Starts a PSCMD channel on the remote end" nocase ascii wide

    condition:
        any of them
}