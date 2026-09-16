rule rule_Earth_Lusca_Operations_Tools_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Earth Lusca Operations Tools' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Earth Lusca Operations Tools"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Earth_Lusca_Operations_Tools_offensive_tool_keyword = " hackergu " nocase ascii wide
                        $string2_Earth_Lusca_Operations_Tools_offensive_tool_keyword = /\.\/agscript\s/
                        $string3_Earth_Lusca_Operations_Tools_offensive_tool_keyword = /\.\/teamserver\s/
                        $string4_Earth_Lusca_Operations_Tools_offensive_tool_keyword = /\/m\s.{0,1000}\.lnk.{0,1000}\s\/c\s.{0,1000}cmd\s\/c\secho\sf\|xcopy\s\@file\s\%temp\%/ nocase ascii wide
                        $string5_Earth_Lusca_Operations_Tools_offensive_tool_keyword = /\\Doraemon/ nocase ascii wide
                        $string6_Earth_Lusca_Operations_Tools_offensive_tool_keyword = /\\macoffe\.pdb/ nocase ascii wide
                        $string7_Earth_Lusca_Operations_Tools_offensive_tool_keyword = /\\mem_dll\.pdb/ nocase ascii wide
                        $string8_Earth_Lusca_Operations_Tools_offensive_tool_keyword = /\\pwn\.exe/ nocase ascii wide
                        $string9_Earth_Lusca_Operations_Tools_offensive_tool_keyword = /\\while_dll_ms/ nocase ascii wide
                        $string10_Earth_Lusca_Operations_Tools_offensive_tool_keyword = /cscript\s.{0,1000}wmi\.vbs\s\-h/ nocase ascii wide
                        $string11_Earth_Lusca_Operations_Tools_offensive_tool_keyword = /findstr\.exe\sTvndrgaaa/ nocase ascii wide
                        $string12_Earth_Lusca_Operations_Tools_offensive_tool_keyword = "fodhelperbypass" nocase ascii wide
                        $string13_Earth_Lusca_Operations_Tools_offensive_tool_keyword = /for\s\/f\s\%\%i\sin\s\(C\:\\Windows\\IME\\ok\.txt\)/ nocase ascii wide
                        $string14_Earth_Lusca_Operations_Tools_offensive_tool_keyword = /for\s\/r\sc\:\\windows\\system32\\\s\%i\sin\s\(.{0,1000}sht.{0,1000}\.exe\)/ nocase ascii wide
                        $string15_Earth_Lusca_Operations_Tools_offensive_tool_keyword = /frpc\.exe\s\-c\sfrpc\.in/ nocase ascii wide
                        $string16_Earth_Lusca_Operations_Tools_offensive_tool_keyword = /libxselinux\.old/
                        $string17_Earth_Lusca_Operations_Tools_offensive_tool_keyword = /libxselinux\.so/
                        $string18_Earth_Lusca_Operations_Tools_offensive_tool_keyword = /megacmd\s\-conf\s.{0,1000}\sput\s.{0,1000}mega\:/ nocase ascii wide
                        $string19_Earth_Lusca_Operations_Tools_offensive_tool_keyword = "net start SysUpdate" nocase ascii wide
                        $string20_Earth_Lusca_Operations_Tools_offensive_tool_keyword = /powershell\s.{0,1000}Get\-EventLog\s\-LogName\ssecurity\s\-Newest\s500\s\|\swhere\s\{\$_\.EventID\s\-eq\s4624\}\s\|\sformat\-list\s\-property\s.{0,1000}\s\|\sfindstr/ nocase ascii wide
                        $string21_Earth_Lusca_Operations_Tools_offensive_tool_keyword = /powershell\sIEX\s\(New\-Object\sNet\.WebClient\)\.DownloadString\(.{0,1000}\)\s\sGet\-NetComputer\s\-FullData\s/ nocase ascii wide
                        $string22_Earth_Lusca_Operations_Tools_offensive_tool_keyword = /powershell\sIEX\s\(New\-Object\sNet\.WebClient\)\.DownloadString.{0,1000}\.ps1.{0,1000}Get\-NetComputer\s\-FullData/ nocase ascii wide
                        $string23_Earth_Lusca_Operations_Tools_offensive_tool_keyword = "PowerShellMafia" nocase ascii wide
                        $string24_Earth_Lusca_Operations_Tools_offensive_tool_keyword = /PowerView\.ps1/ nocase ascii wide
                        $string25_Earth_Lusca_Operations_Tools_offensive_tool_keyword = "Rar a -v3g -k -r -s -m3 " nocase ascii wide
                        $string26_Earth_Lusca_Operations_Tools_offensive_tool_keyword = /tas389\.ps1/ nocase ascii wide
                        $string27_Earth_Lusca_Operations_Tools_offensive_tool_keyword = /ts\.php.{0,1000}vi\.txt/ nocase ascii wide
                        $string28_Earth_Lusca_Operations_Tools_offensive_tool_keyword = /we\.exe\s\-s\srssocks\s\-d\s/ nocase ascii wide
                        $string29_Earth_Lusca_Operations_Tools_offensive_tool_keyword = /wevtutil\sqe\ssecurity\s\/format\:text\s\/q\:.{0,1000}Event\[System\[\(EventID\=4624\)\].{0,1000}find\s.{0,1000}Source\sNetwork\sAddress/ nocase ascii wide
                        $string30_Earth_Lusca_Operations_Tools_offensive_tool_keyword = /xs\.exe\s\-connect\s/ nocase ascii wide

    condition:
        any of them
}