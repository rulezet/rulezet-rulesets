rule EHORUS_RMM
{
    meta:
        description = "Detection patterns for the tool 'EHORUS RMM' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EHORUS RMM"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "\"appName\":\"eHorus Agent\"" nocase ascii wide
                        $string2 = /\$EHORUS_HOME\/\.vnc\/passwd/
                        $string3 = "/ehorus_agent_installer-" nocase ascii wide
                        $string4 = "/etc/ehorus/ehorus_agent"
                        $string5 = /\/etc\/init\.d\/ehorus_agent_daemon/
                        $string6 = "/usr/bin/ehorus_agent"
                        $string7 = "/usr/sbin/userdel -r ehorus"
                        $string8 = "/usr/share/ehorus"
                        $string9 = /\/var\/log\/ehorus_agent\.log/
                        $string10 = /\\eHorus\sAgent\sMenu\.lnk/ nocase ascii wide
                        $string11 = /\\eHorus\sAgent\.lnk/ nocase ascii wide
                        $string12 = /\\ehorus\sstandalone\.exe/ nocase ascii wide
                        $string13 = /\\ehorus_agent\.conf/ nocase ascii wide
                        $string14 = /\\ehorus_agent\.exe/ nocase ascii wide
                        $string15 = /\\ehorus_agent\.log/ nocase ascii wide
                        $string16 = /\\ehorus_agent_disconn\.log/ nocase ascii wide
                        $string17 = /\\ehorus_cmd\.exe/ nocase ascii wide
                        $string18 = /\\ehorus_display\.exe/ nocase ascii wide
                        $string19 = /\\ehorus_installer_windows\-/ nocase ascii wide
                        $string20 = /\\ehorus_launcher\.exe/ nocase ascii wide
                        $string21 = /\\ehorus_uit\.exe/ nocase ascii wide
                        $string22 = /\\eHorusMsiCustomActions\.dll/ nocase ascii wide
                        $string23 = /\\Microsoft\\Windows\\Start\sMenu\\Programs\\eHorus\sAgent\\/ nocase ascii wide
                        $string24 = /\\Program\sFiles\\ehorus_agent\\/ nocase ascii wide
                        $string25 = /\\SOFTWARE\\eHorusDispl\\/ nocase ascii wide
                        $string26 = /\\System\\CurrentControlSet\\Services\\ehorus/ nocase ascii wide
                        $string27 = /\\System\\CurrentControlSet\\Services\\EHORUSAGENT/ nocase ascii wide
                        $string28 = ">eHorus Agent Setup<" nocase ascii wide
                        $string29 = ">EHORUSAGENT<" nocase ascii wide
                        $string30 = "chsh -s /bin/false ehorus"
                        $string31 = "ehorus_agent -f /etc/ehorus/"
                        $string32 = /https\:\/\/portal\.ehorus\.com\/\#\/agents\// nocase ascii wide
                        $string33 = /hub\.ehorus\.com/ nocase ascii wide
                        $string34 = "sc delete ehorus" nocase ascii wide
                        $string35 = "sc stop ehorus" nocase ascii wide
                        $string36 = "su ehorus -s /bin/bash -c \"kill -9 -1\""
                        $string37 = /switch\.ehorus\.com/ nocase ascii wide
                        $string38 = /taskkill\s\/F\s\/IM\s\\"ehorus_agent\.exe\\"/ nocase ascii wide
                        $string39 = /taskkill\s\/F\s\/IM\s\\"ehorus_cmd\.exe\\"/ nocase ascii wide
                        $string40 = /taskkill\s\/F\s\/IM\s\\"ehorus_display\.exe\\"/ nocase ascii wide
                        $string41 = /umount\s\/usr\/share\/ehorus\/\.gvfs\s\-r\s\>\/dev\/null\s2\>\&1/ nocase ascii wide
                        $string42 = /useradd\s\-d\s\/usr\/share\/ehorus\s\-p\s.{0,100}\sehorus/ nocase ascii wide
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