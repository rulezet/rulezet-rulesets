rule anydesk
{
    meta:
        description = "Detection patterns for the tool 'anydesk' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "anydesk"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = " /c echo mar3pora " nocase ascii wide
                        $string2 = /\s\/c\secho\sPa\$\$w0rd\s\|\sC\:\\ProgramData\\anydesk\.exe/ nocase ascii wide
                        $string3 = /\sInvoke\-WebRequest\s\-Uri\shttp\:\/\/download\.anydesk\.com\/AnyDesk\.exe/ nocase ascii wide
                        $string4 = /\$outputPath\s\=\s\\"C\:\\AnyDesk\.exe\\"/ nocase ascii wide
                        $string5 = /\/\.anydesk\/\.anydesk\.trace/
                        $string6 = /\/\.anydesk\/service\.conf/
                        $string7 = /\/\.anydesk\/system\.conf/
                        $string8 = /\/\.anydesk\/user\.conf/
                        $string9 = /\/Anydesk\.exe/ nocase ascii wide
                        $string10 = /\/Applications\/Anydesk\.app\// nocase ascii wide
                        $string11 = /\/etc\/systemd\/system\/anydesk\.service/
                        $string12 = /\/home\/.{0,1000}\/\.anydesk\//
                        $string13 = /\/log\/anydesk\.trace/
                        $string14 = "/usr/bin/anydesk"
                        $string15 = "/usr/lib64/anydesk"
                        $string16 = "/usr/libexec/anydesk"
                        $string17 = /\\ad_svc\.trace/ nocase ascii wide
                        $string18 = /\\adprinterpipe/ nocase ascii wide
                        $string19 = /\\AnyDesk\s\(1\)\.exe/ nocase ascii wide
                        $string20 = /\\AnyDesk\.exe/ nocase ascii wide
                        $string21 = /\\AnyDesk\.lnk/ nocase ascii wide
                        $string22 = /\\AnyDesk\\ad\.trace/ nocase ascii wide
                        $string23 = /\\AnyDesk\\ad_svc\.trace/ nocase ascii wide
                        $string24 = /\\AnyDesk\\AnyDesk_Output\.txt/ nocase ascii wide
                        $string25 = /\\AnyDesk\\connection_trace\.txt/ nocase ascii wide
                        $string26 = /\\AnyDesk\\connection_trace\.txt/ nocase ascii wide
                        $string27 = /\\anydesk\\printer_driver/ nocase ascii wide
                        $string28 = /\\AnyDesk\\service\.conf/ nocase ascii wide
                        $string29 = /\\AnyDeskPrintDriver\.cat/ nocase ascii wide
                        $string30 = /\\anydeskprintdriver\.inf/ nocase ascii wide
                        $string31 = /\\AppData\\Roaming\\AnyDesk\\system\.conf/ nocase ascii wide
                        $string32 = /\\AppData\\Roaming\\AnyDesk\\user\.conf/ nocase ascii wide
                        $string33 = /\\ControlSet001\\Services\\AnyDesk/ nocase ascii wide
                        $string34 = /\\CurrentControlSet\\Control\\SafeBoot\\Network\\AnyDesk/ nocase ascii wide
                        $string35 = /\\file_transfer_trace\.txt/ nocase ascii wide
                        $string36 = /\\Pictures\\AnyDesk/ nocase ascii wide
                        $string37 = /\\Prefetch\\ANYDESK\.EXE/ nocase ascii wide
                        $string38 = /\\ProgramFile.{0,1000}\\previous\-version/ nocase ascii wide
                        $string39 = /\\SOFTWARE\\Clients\\Media\\AnyDesk/ nocase ascii wide
                        $string40 = /\\Temp\\AnyDeskUninst/ nocase ascii wide
                        $string41 = /\\Videos\\AnyDesk/ nocase ascii wide
                        $string42 = "0DBF152DEAF0B981A8A938D53F769DB8" nocase ascii wide
                        $string43 = "9CD1DDB78ED05282353B20CDFE8FA0A4FB6C1ECE" nocase ascii wide
                        $string44 = "9D7620A4CEBA92370E8828B3CB1007AEFF63AB36A2CBE5F044FDDE14ABAB1EBF" nocase ascii wide
                        $string45 = "Ab4y98/VerySimpleAnyDeskBackdoor" nocase ascii wide
                        $string46 = /AnyDesk\sID\sis\:\s\$ID\sAND\sPassword\sis\:\sAa123456\!/ nocase ascii wide
                        $string47 = "AnyDesk Software GmbH" nocase ascii wide
                        $string48 = /Anydesk.{0,1000}\s\-\-start\-with\-win\s\-\-silent/ nocase ascii wide
                        $string49 = /AnyDesk\.exe\s\-\-install\s\\"C\:\\Program\sFiles\s\(x86\)\\AnyDesk\\"\s\-\-start\-with\-win\s\-\-silent/ nocase ascii wide
                        $string50 = /anydesk\.exe\s\-\-set\-password/ nocase ascii wide
                        $string51 = /Anydesk\\ad\.trace/ nocase ascii wide
                        $string52 = /AnydeskBackdoor\.ps1/ nocase ascii wide
                        $string53 = /boot\.net\.anydesk\.com/ nocase ascii wide
                        $string54 = /C\:\\Program\sFiles\s\(x86\)\\AnyDesk/ nocase ascii wide
                        $string55 = /cmd\s\/c\s\'echo\sAa123456\!\s.{0,1000}\s\-\-set\-password/ nocase ascii wide
                        $string56 = /Desktop\\AnyDesk\.lnk/ nocase ascii wide
                        $string57 = /download\.anydesk\.com/ nocase ascii wide
                        $string58 = /HKCR\\\.anydesk\\/ nocase ascii wide
                        $string59 = /programdata\\.{0,1000}\s\-\-start\-with\-win\s\-\-remove\-first\s\-\-silent\s\-\-start\-service/ nocase ascii wide
                        $string60 = /relay\-.{0,1000}\.net\.anydesk\.com/ nocase ascii wide

    condition:
        any of them
}