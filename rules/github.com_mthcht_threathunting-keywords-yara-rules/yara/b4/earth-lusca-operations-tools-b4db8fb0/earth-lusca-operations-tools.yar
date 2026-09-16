rule Earth_Lusca_Operations_Tools
{
    meta:
        description = "Detection patterns for the tool 'Earth Lusca Operations Tools' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Earth Lusca Operations Tools"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " hackergu " nocase ascii wide
                        $string2 = /\.\/agscript\s/
                        $string3 = /\.\/teamserver\s/
                        $string4 = /\/m\s.{0,1000}\.lnk.{0,1000}\s\/c\s.{0,1000}cmd\s\/c\secho\sf\|xcopy\s\@file\s\%temp\%/ nocase ascii wide
                        $string5 = /\\Doraemon/ nocase ascii wide
                        $string6 = /\\macoffe\.pdb/ nocase ascii wide
                        $string7 = /\\mem_dll\.pdb/ nocase ascii wide
                        $string8 = /\\pwn\.exe/ nocase ascii wide
                        $string9 = /\\while_dll_ms/ nocase ascii wide
                        $string10 = /cscript\s.{0,1000}wmi\.vbs\s\-h/ nocase ascii wide
                        $string11 = /findstr\.exe\sTvndrgaaa/ nocase ascii wide
                        $string12 = "fodhelperbypass" nocase ascii wide
                        $string13 = /for\s\/f\s\%\%i\sin\s\(C\:\\Windows\\IME\\ok\.txt\)/ nocase ascii wide
                        $string14 = /for\s\/r\sc\:\\windows\\system32\\\s\%i\sin\s\(.{0,1000}sht.{0,1000}\.exe\)/ nocase ascii wide
                        $string15 = /frpc\.exe\s\-c\sfrpc\.in/ nocase ascii wide
                        $string16 = /libxselinux\.old/
                        $string17 = /libxselinux\.so/
                        $string18 = /megacmd\s\-conf\s.{0,1000}\sput\s.{0,1000}mega\:/ nocase ascii wide
                        $string19 = "net start SysUpdate" nocase ascii wide
                        $string20 = /powershell\s.{0,1000}Get\-EventLog\s\-LogName\ssecurity\s\-Newest\s500\s\|\swhere\s\{\$_\.EventID\s\-eq\s4624\}\s\|\sformat\-list\s\-property\s.{0,1000}\s\|\sfindstr/ nocase ascii wide
                        $string21 = /powershell\sIEX\s\(New\-Object\sNet\.WebClient\)\.DownloadString\(.{0,1000}\)\s\sGet\-NetComputer\s\-FullData\s/ nocase ascii wide
                        $string22 = /powershell\sIEX\s\(New\-Object\sNet\.WebClient\)\.DownloadString.{0,1000}\.ps1.{0,1000}Get\-NetComputer\s\-FullData/ nocase ascii wide
                        $string23 = "PowerShellMafia" nocase ascii wide
                        $string24 = /PowerView\.ps1/ nocase ascii wide
                        $string25 = "Rar a -v3g -k -r -s -m3 " nocase ascii wide
                        $string26 = /tas389\.ps1/ nocase ascii wide
                        $string27 = /ts\.php.{0,1000}vi\.txt/ nocase ascii wide
                        $string28 = /we\.exe\s\-s\srssocks\s\-d\s/ nocase ascii wide
                        $string29 = /wevtutil\sqe\ssecurity\s\/format\:text\s\/q\:.{0,1000}Event\[System\[\(EventID\=4624\)\].{0,1000}find\s.{0,1000}Source\sNetwork\sAddress/ nocase ascii wide
                        $string30 = /xs\.exe\s\-connect\s/ nocase ascii wide

    condition:
        any of them
}