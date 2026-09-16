rule rule_anydesk_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'anydesk' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "anydesk"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_anydesk_greyware_tool_keyword = " /c echo mar3pora " nocase ascii wide
                        $string2_anydesk_greyware_tool_keyword = /\s\/c\secho\sPa\$\$w0rd\s\|\sC\:\\ProgramData\\anydesk\.exe/ nocase ascii wide
                        $string3_anydesk_greyware_tool_keyword = /\sInvoke\-WebRequest\s\-Uri\shttp\:\/\/download\.anydesk\.com\/AnyDesk\.exe/ nocase ascii wide
                        $string4_anydesk_greyware_tool_keyword = /\$outputPath\s\=\s\\"C\:\\AnyDesk\.exe\\"/ nocase ascii wide
                        $string5_anydesk_greyware_tool_keyword = /\/\.anydesk\/\.anydesk\.trace/
                        $string6_anydesk_greyware_tool_keyword = /\/\.anydesk\/service\.conf/
                        $string7_anydesk_greyware_tool_keyword = /\/\.anydesk\/system\.conf/
                        $string8_anydesk_greyware_tool_keyword = /\/\.anydesk\/user\.conf/
                        $string9_anydesk_greyware_tool_keyword = /\/Anydesk\.exe/ nocase ascii wide
                        $string10_anydesk_greyware_tool_keyword = /\/Applications\/Anydesk\.app\// nocase ascii wide
                        $string11_anydesk_greyware_tool_keyword = /\/etc\/systemd\/system\/anydesk\.service/
                        $string12_anydesk_greyware_tool_keyword = /\/home\/.{0,1000}\/\.anydesk\//
                        $string13_anydesk_greyware_tool_keyword = /\/log\/anydesk\.trace/
                        $string14_anydesk_greyware_tool_keyword = "/usr/bin/anydesk"
                        $string15_anydesk_greyware_tool_keyword = "/usr/lib64/anydesk"
                        $string16_anydesk_greyware_tool_keyword = "/usr/libexec/anydesk"
                        $string17_anydesk_greyware_tool_keyword = /\\ad_svc\.trace/ nocase ascii wide
                        $string18_anydesk_greyware_tool_keyword = /\\adprinterpipe/ nocase ascii wide
                        $string19_anydesk_greyware_tool_keyword = /\\AnyDesk\s\(1\)\.exe/ nocase ascii wide
                        $string20_anydesk_greyware_tool_keyword = /\\AnyDesk\.exe/ nocase ascii wide
                        $string21_anydesk_greyware_tool_keyword = /\\AnyDesk\.lnk/ nocase ascii wide
                        $string22_anydesk_greyware_tool_keyword = /\\AnyDesk\\ad\.trace/ nocase ascii wide
                        $string23_anydesk_greyware_tool_keyword = /\\AnyDesk\\ad_svc\.trace/ nocase ascii wide
                        $string24_anydesk_greyware_tool_keyword = /\\AnyDesk\\AnyDesk_Output\.txt/ nocase ascii wide
                        $string25_anydesk_greyware_tool_keyword = /\\AnyDesk\\connection_trace\.txt/ nocase ascii wide
                        $string26_anydesk_greyware_tool_keyword = /\\AnyDesk\\connection_trace\.txt/ nocase ascii wide
                        $string27_anydesk_greyware_tool_keyword = /\\anydesk\\printer_driver/ nocase ascii wide
                        $string28_anydesk_greyware_tool_keyword = /\\AnyDesk\\service\.conf/ nocase ascii wide
                        $string29_anydesk_greyware_tool_keyword = /\\AnyDeskPrintDriver\.cat/ nocase ascii wide
                        $string30_anydesk_greyware_tool_keyword = /\\anydeskprintdriver\.inf/ nocase ascii wide
                        $string31_anydesk_greyware_tool_keyword = /\\AppData\\Roaming\\AnyDesk\\system\.conf/ nocase ascii wide
                        $string32_anydesk_greyware_tool_keyword = /\\AppData\\Roaming\\AnyDesk\\user\.conf/ nocase ascii wide
                        $string33_anydesk_greyware_tool_keyword = /\\ControlSet001\\Services\\AnyDesk/ nocase ascii wide
                        $string34_anydesk_greyware_tool_keyword = /\\CurrentControlSet\\Control\\SafeBoot\\Network\\AnyDesk/ nocase ascii wide
                        $string35_anydesk_greyware_tool_keyword = /\\file_transfer_trace\.txt/ nocase ascii wide
                        $string36_anydesk_greyware_tool_keyword = /\\Pictures\\AnyDesk/ nocase ascii wide
                        $string37_anydesk_greyware_tool_keyword = /\\Prefetch\\ANYDESK\.EXE/ nocase ascii wide
                        $string38_anydesk_greyware_tool_keyword = /\\ProgramFile.{0,1000}\\previous\-version/ nocase ascii wide
                        $string39_anydesk_greyware_tool_keyword = /\\SOFTWARE\\Clients\\Media\\AnyDesk/ nocase ascii wide
                        $string40_anydesk_greyware_tool_keyword = /\\Temp\\AnyDeskUninst/ nocase ascii wide
                        $string41_anydesk_greyware_tool_keyword = /\\Videos\\AnyDesk/ nocase ascii wide
                        $string42_anydesk_greyware_tool_keyword = "0DBF152DEAF0B981A8A938D53F769DB8" nocase ascii wide
                        $string43_anydesk_greyware_tool_keyword = "9CD1DDB78ED05282353B20CDFE8FA0A4FB6C1ECE" nocase ascii wide
                        $string44_anydesk_greyware_tool_keyword = "9D7620A4CEBA92370E8828B3CB1007AEFF63AB36A2CBE5F044FDDE14ABAB1EBF" nocase ascii wide
                        $string45_anydesk_greyware_tool_keyword = "Ab4y98/VerySimpleAnyDeskBackdoor" nocase ascii wide
                        $string46_anydesk_greyware_tool_keyword = /AnyDesk\sID\sis\:\s\$ID\sAND\sPassword\sis\:\sAa123456\!/ nocase ascii wide
                        $string47_anydesk_greyware_tool_keyword = "AnyDesk Software GmbH" nocase ascii wide
                        $string48_anydesk_greyware_tool_keyword = /Anydesk.{0,1000}\s\-\-start\-with\-win\s\-\-silent/ nocase ascii wide
                        $string49_anydesk_greyware_tool_keyword = /AnyDesk\.exe\s\-\-install\s\\"C\:\\Program\sFiles\s\(x86\)\\AnyDesk\\"\s\-\-start\-with\-win\s\-\-silent/ nocase ascii wide
                        $string50_anydesk_greyware_tool_keyword = /anydesk\.exe\s\-\-set\-password/ nocase ascii wide
                        $string51_anydesk_greyware_tool_keyword = /Anydesk\\ad\.trace/ nocase ascii wide
                        $string52_anydesk_greyware_tool_keyword = /AnydeskBackdoor\.ps1/ nocase ascii wide
                        $string53_anydesk_greyware_tool_keyword = /boot\.net\.anydesk\.com/ nocase ascii wide
                        $string54_anydesk_greyware_tool_keyword = /C\:\\Program\sFiles\s\(x86\)\\AnyDesk/ nocase ascii wide
                        $string55_anydesk_greyware_tool_keyword = /cmd\s\/c\s\'echo\sAa123456\!\s.{0,1000}\s\-\-set\-password/ nocase ascii wide
                        $string56_anydesk_greyware_tool_keyword = /Desktop\\AnyDesk\.lnk/ nocase ascii wide
                        $string57_anydesk_greyware_tool_keyword = /download\.anydesk\.com/ nocase ascii wide
                        $string58_anydesk_greyware_tool_keyword = /HKCR\\\.anydesk\\/ nocase ascii wide
                        $string59_anydesk_greyware_tool_keyword = /programdata\\.{0,1000}\s\-\-start\-with\-win\s\-\-remove\-first\s\-\-silent\s\-\-start\-service/ nocase ascii wide
                        $string60_anydesk_greyware_tool_keyword = /relay\-.{0,1000}\.net\.anydesk\.com/ nocase ascii wide

    condition:
        any of them
}