rule level_io
{
    meta:
        description = "Detection patterns for the tool 'level.io' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "level.io"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\s\.\/level\-darwin\-bundle\-amd64\.pkg/
                        $string2 = /\s\.\/level\-linux\-amd64\s/
                        $string3 = /\s\.\/level\-linux\-arm64\s/
                        $string4 = /\s\/F\s\/TN\s\\"Level\\Level\sWatchdog\\"/ nocase ascii wide
                        $string5 = /\sdownloads\.level\.io/ nocase ascii wide
                        $string6 = /\\"message\\"\:\\"ably\sconnection\sstate\:\sCONNECTED\\"\}/ nocase ascii wide
                        $string7 = /\$env\:LEVEL_API_KEY\s\=\s\\".{0,1000}\\"\;/ nocase ascii wide
                        $string8 = /\$tempFile\s\=\sJoin\-Path\s\(\[System\.IO\.Path\]\:\:GetTempPath\(\)\)\s\\"install_windows\.exe\\"\;/ nocase ascii wide
                        $string9 = /\/etc\/level\/config\.yaml/
                        $string10 = /\/level\-windows\-amd64\.exe/ nocase ascii wide
                        $string11 = /\/level\-windows\-arm64\.exe/ nocase ascii wide
                        $string12 = "/usr/local/bin/level"
                        $string13 = /\/var\/lib\/level\/level\.db/
                        $string14 = /\/var\/lib\/level\/level\.log/
                        $string15 = /\\level\.exe.{0,1000}\-\-check\-service/ nocase ascii wide
                        $string16 = /\\level\-remote\-control\-ffmpeg\.exe\.download/ nocase ascii wide
                        $string17 = /\\level\-windows\-amd64\.exe/ nocase ascii wide
                        $string18 = /\\level\-windows\-arm64\.exe/ nocase ascii wide
                        $string19 = /\\Program\sFiles\s\(x86\)\\Level\\/ nocase ascii wide
                        $string20 = /\\Program\sFiles\\Level\\level\.db/ nocase ascii wide
                        $string21 = /\\Program\sFiles\\Level\\osqueryi\.exe/ nocase ascii wide
                        $string22 = /\\Program\sFiles\\Level\\winpty\.dll/ nocase ascii wide
                        $string23 = /\\Program\sFiles\\Level\\winpty\-agent\.exe/ nocase ascii wide
                        $string24 = /\\Temp\\install_windows\.exe/ nocase ascii wide
                        $string25 = /\<\\Level\\Level\sWatchdog\>/ nocase ascii wide
                        $string26 = /\>Level\sSoftware\,\sInc\.\</ nocase ascii wide
                        $string27 = /\>Remote\sdevice\smanagement\s\-\shttps\:\/\/level\.io\</ nocase ascii wide
                        $string28 = "37B9B43761672219E98BFA826E7AF17E799592BC57ACBC4AAC38DAF5EFAAF653" nocase ascii wide
                        $string29 = "3DDF7FBB35EC90BCF15E723F1445EEB71E71C9757243EFEC1CEB4E74A10A1D9F" nocase ascii wide
                        $string30 = /agents\.level\.io/ nocase ascii wide
                        $string31 = /builds\.level\.io/ nocase ascii wide
                        $string32 = /https\:\/\/app\.level\.io\/devices/ nocase ascii wide
                        $string33 = /https\:\/\/docs\.level\.io\/1\.0\/admin\-guides\/level\-watchdog\-task/ nocase ascii wide
                        $string34 = /https\:\/\/downloads\.level\.io\/install_linux\.sh/
                        $string35 = /https\:\/\/downloads\.level\.io\/install_mac_os\.sh/ nocase ascii wide
                        $string36 = /https\:\/\/downloads\.level\.io\/install_windows\.exe/ nocase ascii wide
                        $string37 = /https\:\/\/downloads\.level\.io\/stable\/level\-linux\-amd64/
                        $string38 = /LEVEL_API_KEY\=.{0,1000}\sbash\s\-c\s\\"\$\(curl\s\-L\s/
                        $string39 = /logs\.logdna\.com/ nocase ascii wide
                        $string40 = /netsh\s\sadvfirewall\sfirewall\sadd\srule\sname\=\\\\"Level\sAgent\\\\"/ nocase ascii wide
                        $string41 = /online\.level\.io/ nocase ascii wide
                        $string42 = /Program\sFiles\\Level\\level\.log/ nocase ascii wide
                        $string43 = /realtime\.ably\.io/ nocase ascii wide
                        $string44 = /rest\.ably\.io/ nocase ascii wide

    condition:
        any of them
}