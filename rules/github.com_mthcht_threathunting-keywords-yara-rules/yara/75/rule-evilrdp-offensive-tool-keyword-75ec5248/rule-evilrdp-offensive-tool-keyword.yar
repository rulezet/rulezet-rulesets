rule rule_evilrdp_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'evilrdp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "evilrdp"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_evilrdp_offensive_tool_keyword = /\sevilrdp\.gui\s/ nocase ascii wide
                        $string2_evilrdp_offensive_tool_keyword = /\/evilrdp\.git/ nocase ascii wide
                        $string3_evilrdp_offensive_tool_keyword = "/evilrdp/" nocase ascii wide
                        $string4_evilrdp_offensive_tool_keyword = /\\evilrdp\\/ nocase ascii wide
                        $string5_evilrdp_offensive_tool_keyword = /aardwolf\.extensions\.RDPEDYC\.vchannels\.socksoverrdp\simport\sSocksOverRDPChannel/ nocase ascii wide
                        $string6_evilrdp_offensive_tool_keyword = /aiocmd\\nested_completer\.py/ nocase ascii wide
                        $string7_evilrdp_offensive_tool_keyword = /Async\sRDP\sClient\.\sDuckyscript\swill\sbe\sexecuted\sby\spressing\sESC\s3\stimes/ nocase ascii wide
                        $string8_evilrdp_offensive_tool_keyword = /do_socksoverrdp\(.{0,100}127\.0\.0\.1/ nocase ascii wide
                        $string9_evilrdp_offensive_tool_keyword = /do_socksproxy\(.{0,100}\slisten_ip\s\=\s\'127\.0\.0\.1\'/ nocase ascii wide
                        $string10_evilrdp_offensive_tool_keyword = /do_startpscmd\(.{0,100}serverscript\.ps1/ nocase ascii wide
                        $string11_evilrdp_offensive_tool_keyword = /ducky_keyboard_sender\(scancode/ nocase ascii wide
                        $string12_evilrdp_offensive_tool_keyword = "Emulates a rightclick on the given coordinates" nocase ascii wide
                        $string13_evilrdp_offensive_tool_keyword = /evilrdp\.exe/ nocase ascii wide
                        $string14_evilrdp_offensive_tool_keyword = "evilrdp-main" nocase ascii wide
                        $string15_evilrdp_offensive_tool_keyword = /Executes\sa\spowershell\scommand\son\sthe\sremote\shost\.\sRequires\sPSCMD/ nocase ascii wide
                        $string16_evilrdp_offensive_tool_keyword = /from\sevilrdp\.consolehelper/ nocase ascii wide
                        $string17_evilrdp_offensive_tool_keyword = "import EVILRDPConsole" nocase ascii wide
                        $string18_evilrdp_offensive_tool_keyword = "import EvilRDPGUI" nocase ascii wide
                        $string19_evilrdp_offensive_tool_keyword = /PSCMD\schannel\swas\seither\snot\sdefined\swhile\sconnecting\sOR\sthe\schannel\sname\sis\snot\sthe\sdefault\./ nocase ascii wide
                        $string20_evilrdp_offensive_tool_keyword = /pscmd\/serverscript\.ps1/ nocase ascii wide
                        $string21_evilrdp_offensive_tool_keyword = /pscmd\\serverscript\.ps1/ nocase ascii wide
                        $string22_evilrdp_offensive_tool_keyword = /rdp\+kerberos\-password\:\/\/.{0,100}\?dc\=.{0,100}proxytype.{0,100}proxyhost/ nocase ascii wide
                        $string23_evilrdp_offensive_tool_keyword = /rdp\+ntlm\-password\:\/\/.{0,100}\@/ nocase ascii wide
                        $string24_evilrdp_offensive_tool_keyword = /sendcmd\(.{0,100}cmd\:PSCMDMessage/ nocase ascii wide
                        $string25_evilrdp_offensive_tool_keyword = "Set the correct channel name using \"\"pscmdchannel\"\" command" nocase ascii wide
                        $string26_evilrdp_offensive_tool_keyword = "skelsec/evilrdp" nocase ascii wide
                        $string27_evilrdp_offensive_tool_keyword = "Starts a PSCMD channel on the remote end" nocase ascii wide
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