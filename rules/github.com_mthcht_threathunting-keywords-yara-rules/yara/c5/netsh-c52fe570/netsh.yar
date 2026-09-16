rule netsh
{
    meta:
        description = "Detection patterns for the tool 'netsh' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "netsh"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\sadvfirewall\sfirewall\sadd\srule\s.{0,100}\sdir\=in\sprotocol\=tcp\slocalport\=3389\saction\=allow/ nocase ascii wide
                        $string2 = /\\netsh\.exe\\"\swlan\sshow\sprofiles/ nocase ascii wide
                        $string3 = /for\s\/L\s\%i\sin\s\(2\,1\,254\)\sdo\s\(netsh\sinterface\sip\sset\saddress\slocal\sstatic/ nocase ascii wide
                        $string4 = "netsh advfirewall firewall add rule name=\"allow RDP\" dir=in protocol=TCP localport=3389 action=allow" nocase ascii wide
                        $string5 = "netsh advfirewall firewall show rule name=all" nocase ascii wide
                        $string6 = "netsh advfirewall set allprofiles state off" nocase ascii wide
                        $string7 = "NetSh Advfirewall set allprofiles state off" nocase ascii wide
                        $string8 = /netsh\sfirewall\sadd\sallowedprogram\s\\"C\:\\Users\\.{0,100}\\AppData\\.{0,100}\.exe\\"\s\\".{0,100}\.exe\\"\sENABLE/ nocase ascii wide
                        $string9 = "netsh firewall delete allowedprogram " nocase ascii wide
                        $string10 = "netsh firewall set opmode disable" nocase ascii wide
                        $string11 = "netsh firewall show all" nocase ascii wide
                        $string12 = "netsh firewall show config" nocase ascii wide
                        $string13 = "netsh interface firewall show all" nocase ascii wide
                        $string14 = /netsh\sinterface\sportproxy\sadd\sv4tov4\slistenport\=.{0,100}\sconnectaddress\=/ nocase ascii wide
                        $string15 = /netsh\sinterface\sportproxy\sadd\sv4tov4.{0,100}listenaddress\=.{0,100}\slistenport\=.{0,100}connectaddress\=.{0,100}connectport/ nocase ascii wide
                        $string16 = /netsh\sinterface\sportproxy\sdelete\sv4tov4\slistenaddress\=0\.0\.0\.0\slistenport\=/ nocase ascii wide
                        $string17 = "netsh interface portproxy delete v4tov4 listenport=" nocase ascii wide
                        $string18 = "netsh interface portproxy show all" nocase ascii wide
                        $string19 = "netsh interface portproxy show v4tov4" nocase ascii wide
                        $string20 = "netsh portproxy show v4tov4" nocase ascii wide
                        $string21 = /netsh\swlan\sshow\sprofiles\s.{0,100}key\=clear/ nocase ascii wide
                        $string22 = /netsh\.exe\sadvfirewall\sfirewall\sadd\srule\s\\"name\=allow\sRemoteDesktop\\"\sdir\=in\s.{0,100}\slocalport\=.{0,100}\saction\=allow/ nocase ascii wide
                        $string23 = /netsh\.exe\sadvfirewall\sfirewall\sset\srule\s\\"group\=remote\sdesktop\\"\snew\senable\=Yes/ nocase ascii wide
                        $string24 = /netsh\.exe\strace\sstart\smaxSize\=1\sfileMode\=single\scapture\=yes\straceFile\=.{0,100}\\TEMP.{0,100}\.etl/ nocase ascii wide
                        $string25 = /netsh\.exe\swlan\sshow\sprofiles\skey\=clear/ nocase ascii wide
                        $string26 = /netsh\.exe.{0,100}\sinterface\sportproxy\sshow\sall/ nocase ascii wide
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