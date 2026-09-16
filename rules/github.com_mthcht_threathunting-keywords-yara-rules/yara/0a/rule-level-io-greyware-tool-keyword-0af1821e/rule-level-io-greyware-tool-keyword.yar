rule rule_level_io_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'level.io' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "level.io"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_level_io_greyware_tool_keyword = /\s\.\/level\-darwin\-bundle\-amd64\.pkg/
                        $string2_level_io_greyware_tool_keyword = /\s\.\/level\-linux\-amd64\s/
                        $string3_level_io_greyware_tool_keyword = /\s\.\/level\-linux\-arm64\s/
                        $string4_level_io_greyware_tool_keyword = /\s\/F\s\/TN\s\\"Level\\Level\sWatchdog\\"/ nocase ascii wide
                        $string5_level_io_greyware_tool_keyword = /\sdownloads\.level\.io/ nocase ascii wide
                        $string6_level_io_greyware_tool_keyword = /\\"message\\"\:\\"ably\sconnection\sstate\:\sCONNECTED\\"\}/ nocase ascii wide
                        $string7_level_io_greyware_tool_keyword = /\$env\:LEVEL_API_KEY\s\=\s\\".{0,1000}\\"\;/ nocase ascii wide
                        $string8_level_io_greyware_tool_keyword = /\$tempFile\s\=\sJoin\-Path\s\(\[System\.IO\.Path\]\:\:GetTempPath\(\)\)\s\\"install_windows\.exe\\"\;/ nocase ascii wide
                        $string9_level_io_greyware_tool_keyword = /\/etc\/level\/config\.yaml/
                        $string10_level_io_greyware_tool_keyword = /\/level\-windows\-amd64\.exe/ nocase ascii wide
                        $string11_level_io_greyware_tool_keyword = /\/level\-windows\-arm64\.exe/ nocase ascii wide
                        $string12_level_io_greyware_tool_keyword = "/usr/local/bin/level"
                        $string13_level_io_greyware_tool_keyword = /\/var\/lib\/level\/level\.db/
                        $string14_level_io_greyware_tool_keyword = /\/var\/lib\/level\/level\.log/
                        $string15_level_io_greyware_tool_keyword = /\\level\.exe.{0,1000}\-\-check\-service/ nocase ascii wide
                        $string16_level_io_greyware_tool_keyword = /\\level\-remote\-control\-ffmpeg\.exe\.download/ nocase ascii wide
                        $string17_level_io_greyware_tool_keyword = /\\level\-windows\-amd64\.exe/ nocase ascii wide
                        $string18_level_io_greyware_tool_keyword = /\\level\-windows\-arm64\.exe/ nocase ascii wide
                        $string19_level_io_greyware_tool_keyword = /\\Program\sFiles\s\(x86\)\\Level\\/ nocase ascii wide
                        $string20_level_io_greyware_tool_keyword = /\\Program\sFiles\\Level\\level\.db/ nocase ascii wide
                        $string21_level_io_greyware_tool_keyword = /\\Program\sFiles\\Level\\osqueryi\.exe/ nocase ascii wide
                        $string22_level_io_greyware_tool_keyword = /\\Program\sFiles\\Level\\winpty\.dll/ nocase ascii wide
                        $string23_level_io_greyware_tool_keyword = /\\Program\sFiles\\Level\\winpty\-agent\.exe/ nocase ascii wide
                        $string24_level_io_greyware_tool_keyword = /\\Temp\\install_windows\.exe/ nocase ascii wide
                        $string25_level_io_greyware_tool_keyword = /\<\\Level\\Level\sWatchdog\>/ nocase ascii wide
                        $string26_level_io_greyware_tool_keyword = /\>Level\sSoftware\,\sInc\.\</ nocase ascii wide
                        $string27_level_io_greyware_tool_keyword = /\>Remote\sdevice\smanagement\s\-\shttps\:\/\/level\.io\</ nocase ascii wide
                        $string28_level_io_greyware_tool_keyword = "37B9B43761672219E98BFA826E7AF17E799592BC57ACBC4AAC38DAF5EFAAF653" nocase ascii wide
                        $string29_level_io_greyware_tool_keyword = "3DDF7FBB35EC90BCF15E723F1445EEB71E71C9757243EFEC1CEB4E74A10A1D9F" nocase ascii wide
                        $string30_level_io_greyware_tool_keyword = /agents\.level\.io/ nocase ascii wide
                        $string31_level_io_greyware_tool_keyword = /builds\.level\.io/ nocase ascii wide
                        $string32_level_io_greyware_tool_keyword = /https\:\/\/app\.level\.io\/devices/ nocase ascii wide
                        $string33_level_io_greyware_tool_keyword = /https\:\/\/docs\.level\.io\/1\.0\/admin\-guides\/level\-watchdog\-task/ nocase ascii wide
                        $string34_level_io_greyware_tool_keyword = /https\:\/\/downloads\.level\.io\/install_linux\.sh/
                        $string35_level_io_greyware_tool_keyword = /https\:\/\/downloads\.level\.io\/install_mac_os\.sh/ nocase ascii wide
                        $string36_level_io_greyware_tool_keyword = /https\:\/\/downloads\.level\.io\/install_windows\.exe/ nocase ascii wide
                        $string37_level_io_greyware_tool_keyword = /https\:\/\/downloads\.level\.io\/stable\/level\-linux\-amd64/
                        $string38_level_io_greyware_tool_keyword = /LEVEL_API_KEY\=.{0,1000}\sbash\s\-c\s\\"\$\(curl\s\-L\s/
                        $string39_level_io_greyware_tool_keyword = /logs\.logdna\.com/ nocase ascii wide
                        $string40_level_io_greyware_tool_keyword = /netsh\s\sadvfirewall\sfirewall\sadd\srule\sname\=\\\\"Level\sAgent\\\\"/ nocase ascii wide
                        $string41_level_io_greyware_tool_keyword = /online\.level\.io/ nocase ascii wide
                        $string42_level_io_greyware_tool_keyword = /Program\sFiles\\Level\\level\.log/ nocase ascii wide
                        $string43_level_io_greyware_tool_keyword = /realtime\.ably\.io/ nocase ascii wide
                        $string44_level_io_greyware_tool_keyword = /rest\.ably\.io/ nocase ascii wide

    condition:
        any of them
}