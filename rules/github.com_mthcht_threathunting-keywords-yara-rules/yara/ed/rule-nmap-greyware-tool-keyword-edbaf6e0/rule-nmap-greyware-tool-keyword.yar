rule rule_nmap_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'nmap' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nmap"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_nmap_greyware_tool_keyword = " --script smb-vuln-ms08-067,smb-vuln-ms17-010" nocase ascii wide
                        $string2_nmap_greyware_tool_keyword = /\.\/nmap/
                        $string3_nmap_greyware_tool_keyword = /\.\/test\/nmap.{0,1000}\/.{0,1000}\.nse/
                        $string4_nmap_greyware_tool_keyword = "/Nmap/folder/check15" nocase ascii wide
                        $string5_nmap_greyware_tool_keyword = "/Nmap/folder/check16" nocase ascii wide
                        $string6_nmap_greyware_tool_keyword = "/Nmap/folder/check17" nocase ascii wide
                        $string7_nmap_greyware_tool_keyword = "/nmaplowercheck15" nocase ascii wide
                        $string8_nmap_greyware_tool_keyword = "/nmaplowercheck16" nocase ascii wide
                        $string9_nmap_greyware_tool_keyword = "/nmaplowercheck17" nocase ascii wide
                        $string10_nmap_greyware_tool_keyword = "/nmap-nse-scripts"
                        $string11_nmap_greyware_tool_keyword = "/nmap-scada" nocase ascii wide
                        $string12_nmap_greyware_tool_keyword = "/NmapUpperCheck15" nocase ascii wide
                        $string13_nmap_greyware_tool_keyword = "/NmapUpperCheck16" nocase ascii wide
                        $string14_nmap_greyware_tool_keyword = "/NmapUpperCheck17" nocase ascii wide
                        $string15_nmap_greyware_tool_keyword = "/nmap-vulners" nocase ascii wide
                        $string16_nmap_greyware_tool_keyword = "/nse_install/"
                        $string17_nmap_greyware_tool_keyword = /\/nse\-install\.git/ nocase ascii wide
                        $string18_nmap_greyware_tool_keyword = "/s4n7h0/NSE"
                        $string19_nmap_greyware_tool_keyword = /\\nmap\.exe.{0,1000}\/24/ nocase ascii wide
                        $string20_nmap_greyware_tool_keyword = "b4ldr/nse-scripts" nocase ascii wide
                        $string21_nmap_greyware_tool_keyword = "external-nse-script-library" nocase ascii wide
                        $string22_nmap_greyware_tool_keyword = /ifconfig\s\-a\s\|\sgrep\s.{0,1000}\s\|\sxargs\snmap\s\-/ nocase ascii wide
                        $string23_nmap_greyware_tool_keyword = "nmap -" nocase ascii wide
                        $string24_nmap_greyware_tool_keyword = /nmap\s.{0,1000}\s\-\-script\=.{0,1000}\.nse/ nocase ascii wide
                        $string25_nmap_greyware_tool_keyword = /nmap\s\-p\s445\s.{0,1000}\s\-sS\s\-\-script\ssmb\-security\-mode/ nocase ascii wide
                        $string26_nmap_greyware_tool_keyword = /nmap\-.{0,1000}\-setup\.exe/ nocase ascii wide
                        $string27_nmap_greyware_tool_keyword = "nmap-elasticsearch-nse" nocase ascii wide
                        $string28_nmap_greyware_tool_keyword = /nse_install\.py/ nocase ascii wide
                        $string29_nmap_greyware_tool_keyword = /nse\-insall\-0\.0\.1/ nocase ascii wide
                        $string30_nmap_greyware_tool_keyword = "nse-install " nocase ascii wide
                        $string31_nmap_greyware_tool_keyword = "nse-install-master" nocase ascii wide
                        $string32_nmap_greyware_tool_keyword = "OCSAF/freevulnsearch" nocase ascii wide
                        $string33_nmap_greyware_tool_keyword = /os\.execute\(.{0,1000}\/bin\/.{0,1000}nmap\s\-\-script\=\$/
                        $string34_nmap_greyware_tool_keyword = "psc4re/NSE-scripts" nocase ascii wide
                        $string35_nmap_greyware_tool_keyword = "remiflavien1/nse-install" nocase ascii wide
                        $string36_nmap_greyware_tool_keyword = "shadawck/nse-install" nocase ascii wide
                        $string37_nmap_greyware_tool_keyword = "takeshixx/nmap-scripts" nocase ascii wide
                        $string38_nmap_greyware_tool_keyword = /zenmap\.exe/ nocase ascii wide
                        $string39_nmap_greyware_tool_keyword = "zmap -" nocase ascii wide

    condition:
        any of them
}