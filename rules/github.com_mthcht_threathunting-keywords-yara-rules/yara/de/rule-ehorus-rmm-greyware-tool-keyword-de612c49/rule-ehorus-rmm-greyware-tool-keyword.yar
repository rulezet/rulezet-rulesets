rule rule_EHORUS_RMM_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'EHORUS RMM' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EHORUS RMM"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_EHORUS_RMM_greyware_tool_keyword = "\"appName\":\"eHorus Agent\"" nocase ascii wide
                        $string2_EHORUS_RMM_greyware_tool_keyword = /\$EHORUS_HOME\/\.vnc\/passwd/
                        $string3_EHORUS_RMM_greyware_tool_keyword = "/ehorus_agent_installer-" nocase ascii wide
                        $string4_EHORUS_RMM_greyware_tool_keyword = "/etc/ehorus/ehorus_agent"
                        $string5_EHORUS_RMM_greyware_tool_keyword = /\/etc\/init\.d\/ehorus_agent_daemon/
                        $string6_EHORUS_RMM_greyware_tool_keyword = "/usr/bin/ehorus_agent"
                        $string7_EHORUS_RMM_greyware_tool_keyword = "/usr/sbin/userdel -r ehorus"
                        $string8_EHORUS_RMM_greyware_tool_keyword = "/usr/share/ehorus"
                        $string9_EHORUS_RMM_greyware_tool_keyword = /\/var\/log\/ehorus_agent\.log/
                        $string10_EHORUS_RMM_greyware_tool_keyword = /\\eHorus\sAgent\sMenu\.lnk/ nocase ascii wide
                        $string11_EHORUS_RMM_greyware_tool_keyword = /\\eHorus\sAgent\.lnk/ nocase ascii wide
                        $string12_EHORUS_RMM_greyware_tool_keyword = /\\ehorus\sstandalone\.exe/ nocase ascii wide
                        $string13_EHORUS_RMM_greyware_tool_keyword = /\\ehorus_agent\.conf/ nocase ascii wide
                        $string14_EHORUS_RMM_greyware_tool_keyword = /\\ehorus_agent\.exe/ nocase ascii wide
                        $string15_EHORUS_RMM_greyware_tool_keyword = /\\ehorus_agent\.log/ nocase ascii wide
                        $string16_EHORUS_RMM_greyware_tool_keyword = /\\ehorus_agent_disconn\.log/ nocase ascii wide
                        $string17_EHORUS_RMM_greyware_tool_keyword = /\\ehorus_cmd\.exe/ nocase ascii wide
                        $string18_EHORUS_RMM_greyware_tool_keyword = /\\ehorus_display\.exe/ nocase ascii wide
                        $string19_EHORUS_RMM_greyware_tool_keyword = /\\ehorus_installer_windows\-/ nocase ascii wide
                        $string20_EHORUS_RMM_greyware_tool_keyword = /\\ehorus_launcher\.exe/ nocase ascii wide
                        $string21_EHORUS_RMM_greyware_tool_keyword = /\\ehorus_uit\.exe/ nocase ascii wide
                        $string22_EHORUS_RMM_greyware_tool_keyword = /\\eHorusMsiCustomActions\.dll/ nocase ascii wide
                        $string23_EHORUS_RMM_greyware_tool_keyword = /\\Microsoft\\Windows\\Start\sMenu\\Programs\\eHorus\sAgent\\/ nocase ascii wide
                        $string24_EHORUS_RMM_greyware_tool_keyword = /\\Program\sFiles\\ehorus_agent\\/ nocase ascii wide
                        $string25_EHORUS_RMM_greyware_tool_keyword = /\\SOFTWARE\\eHorusDispl\\/ nocase ascii wide
                        $string26_EHORUS_RMM_greyware_tool_keyword = /\\System\\CurrentControlSet\\Services\\ehorus/ nocase ascii wide
                        $string27_EHORUS_RMM_greyware_tool_keyword = /\\System\\CurrentControlSet\\Services\\EHORUSAGENT/ nocase ascii wide
                        $string28_EHORUS_RMM_greyware_tool_keyword = ">eHorus Agent Setup<" nocase ascii wide
                        $string29_EHORUS_RMM_greyware_tool_keyword = ">EHORUSAGENT<" nocase ascii wide
                        $string30_EHORUS_RMM_greyware_tool_keyword = "chsh -s /bin/false ehorus"
                        $string31_EHORUS_RMM_greyware_tool_keyword = "ehorus_agent -f /etc/ehorus/"
                        $string32_EHORUS_RMM_greyware_tool_keyword = /https\:\/\/portal\.ehorus\.com\/\#\/agents\// nocase ascii wide
                        $string33_EHORUS_RMM_greyware_tool_keyword = /hub\.ehorus\.com/ nocase ascii wide
                        $string34_EHORUS_RMM_greyware_tool_keyword = "sc delete ehorus" nocase ascii wide
                        $string35_EHORUS_RMM_greyware_tool_keyword = "sc stop ehorus" nocase ascii wide
                        $string36_EHORUS_RMM_greyware_tool_keyword = "su ehorus -s /bin/bash -c \"kill -9 -1\""
                        $string37_EHORUS_RMM_greyware_tool_keyword = /switch\.ehorus\.com/ nocase ascii wide
                        $string38_EHORUS_RMM_greyware_tool_keyword = /taskkill\s\/F\s\/IM\s\\"ehorus_agent\.exe\\"/ nocase ascii wide
                        $string39_EHORUS_RMM_greyware_tool_keyword = /taskkill\s\/F\s\/IM\s\\"ehorus_cmd\.exe\\"/ nocase ascii wide
                        $string40_EHORUS_RMM_greyware_tool_keyword = /taskkill\s\/F\s\/IM\s\\"ehorus_display\.exe\\"/ nocase ascii wide
                        $string41_EHORUS_RMM_greyware_tool_keyword = /umount\s\/usr\/share\/ehorus\/\.gvfs\s\-r\s\>\/dev\/null\s2\>\&1/ nocase ascii wide
                        $string42_EHORUS_RMM_greyware_tool_keyword = /useradd\s\-d\s\/usr\/share\/ehorus\s\-p\s.{0,100}\sehorus/ nocase ascii wide
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