rule netsh
{
    meta:
        description = "Detection patterns for the tool 'netsh' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "netsh"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\sadvfirewall\sfirewall\sadd\srule\s.{0,1000}\sdir\=in\sprotocol\=tcp\slocalport\=3389\saction\=allow/ nocase ascii wide
                        $string2 = /\\netsh\.exe\\"\swlan\sshow\sprofiles/ nocase ascii wide
                        $string3 = /for\s\/L\s\%i\sin\s\(2\,1\,254\)\sdo\s\(netsh\sinterface\sip\sset\saddress\slocal\sstatic/ nocase ascii wide
                        $string4 = "netsh advfirewall firewall add rule name=\"allow RDP\" dir=in protocol=TCP localport=3389 action=allow" nocase ascii wide
                        $string5 = "netsh advfirewall firewall show rule name=all" nocase ascii wide
                        $string6 = "netsh advfirewall set allprofiles state off" nocase ascii wide
                        $string7 = "NetSh Advfirewall set allprofiles state off" nocase ascii wide
                        $string8 = /netsh\sfirewall\sadd\sallowedprogram\s\\"C\:\\Users\\.{0,1000}\\AppData\\.{0,1000}\.exe\\"\s\\".{0,1000}\.exe\\"\sENABLE/ nocase ascii wide
                        $string9 = "netsh firewall delete allowedprogram " nocase ascii wide
                        $string10 = "netsh firewall set opmode disable" nocase ascii wide
                        $string11 = "netsh firewall show all" nocase ascii wide
                        $string12 = "netsh firewall show config" nocase ascii wide
                        $string13 = "netsh interface firewall show all" nocase ascii wide
                        $string14 = /netsh\sinterface\sportproxy\sadd\sv4tov4\slistenport\=.{0,1000}\sconnectaddress\=/ nocase ascii wide
                        $string15 = /netsh\sinterface\sportproxy\sadd\sv4tov4.{0,1000}listenaddress\=.{0,1000}\slistenport\=.{0,1000}connectaddress\=.{0,1000}connectport/ nocase ascii wide
                        $string16 = /netsh\sinterface\sportproxy\sdelete\sv4tov4\slistenaddress\=0\.0\.0\.0\slistenport\=/ nocase ascii wide
                        $string17 = "netsh interface portproxy delete v4tov4 listenport=" nocase ascii wide
                        $string18 = "netsh interface portproxy show all" nocase ascii wide
                        $string19 = "netsh interface portproxy show v4tov4" nocase ascii wide
                        $string20 = "netsh portproxy show v4tov4" nocase ascii wide
                        $string21 = /netsh\swlan\sshow\sprofiles\s.{0,1000}key\=clear/ nocase ascii wide
                        $string22 = /netsh\.exe\sadvfirewall\sfirewall\sadd\srule\s\\"name\=allow\sRemoteDesktop\\"\sdir\=in\s.{0,1000}\slocalport\=.{0,1000}\saction\=allow/ nocase ascii wide
                        $string23 = /netsh\.exe\sadvfirewall\sfirewall\sset\srule\s\\"group\=remote\sdesktop\\"\snew\senable\=Yes/ nocase ascii wide
                        $string24 = /netsh\.exe\strace\sstart\smaxSize\=1\sfileMode\=single\scapture\=yes\straceFile\=.{0,1000}\\TEMP.{0,1000}\.etl/ nocase ascii wide
                        $string25 = /netsh\.exe\swlan\sshow\sprofiles\skey\=clear/ nocase ascii wide
                        $string26 = /netsh\.exe.{0,1000}\sinterface\sportproxy\sshow\sall/ nocase ascii wide

    condition:
        any of them
}