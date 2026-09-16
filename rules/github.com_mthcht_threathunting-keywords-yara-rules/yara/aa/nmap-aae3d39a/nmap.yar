rule nmap
{
    meta:
        description = "Detection patterns for the tool 'nmap' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nmap"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = " --script smb-vuln-ms08-067,smb-vuln-ms17-010" nocase ascii wide
                        $string2 = /\.\/nmap/
                        $string3 = /\.\/test\/nmap.{0,1000}\/.{0,1000}\.nse/
                        $string4 = "/Nmap/folder/check15" nocase ascii wide
                        $string5 = "/Nmap/folder/check16" nocase ascii wide
                        $string6 = "/Nmap/folder/check17" nocase ascii wide
                        $string7 = "/nmaplowercheck15" nocase ascii wide
                        $string8 = "/nmaplowercheck16" nocase ascii wide
                        $string9 = "/nmaplowercheck17" nocase ascii wide
                        $string10 = "/nmap-nse-scripts"
                        $string11 = "/nmap-scada" nocase ascii wide
                        $string12 = "/NmapUpperCheck15" nocase ascii wide
                        $string13 = "/NmapUpperCheck16" nocase ascii wide
                        $string14 = "/NmapUpperCheck17" nocase ascii wide
                        $string15 = "/nmap-vulners" nocase ascii wide
                        $string16 = "/nse_install/"
                        $string17 = /\/nse\-install\.git/ nocase ascii wide
                        $string18 = "/s4n7h0/NSE"
                        $string19 = /\\nmap\.exe.{0,1000}\/24/ nocase ascii wide
                        $string20 = "b4ldr/nse-scripts" nocase ascii wide
                        $string21 = "external-nse-script-library" nocase ascii wide
                        $string22 = /ifconfig\s\-a\s\|\sgrep\s.{0,1000}\s\|\sxargs\snmap\s\-/ nocase ascii wide
                        $string23 = "nmap -" nocase ascii wide
                        $string24 = /nmap\s.{0,1000}\s\-\-script\=.{0,1000}\.nse/ nocase ascii wide
                        $string25 = /nmap\s\-p\s445\s.{0,1000}\s\-sS\s\-\-script\ssmb\-security\-mode/ nocase ascii wide
                        $string26 = /nmap\-.{0,1000}\-setup\.exe/ nocase ascii wide
                        $string27 = "nmap-elasticsearch-nse" nocase ascii wide
                        $string28 = /nse_install\.py/ nocase ascii wide
                        $string29 = /nse\-insall\-0\.0\.1/ nocase ascii wide
                        $string30 = "nse-install " nocase ascii wide
                        $string31 = "nse-install-master" nocase ascii wide
                        $string32 = "OCSAF/freevulnsearch" nocase ascii wide
                        $string33 = /os\.execute\(.{0,1000}\/bin\/.{0,1000}nmap\s\-\-script\=\$/
                        $string34 = "psc4re/NSE-scripts" nocase ascii wide
                        $string35 = "remiflavien1/nse-install" nocase ascii wide
                        $string36 = "shadawck/nse-install" nocase ascii wide
                        $string37 = "takeshixx/nmap-scripts" nocase ascii wide
                        $string38 = /zenmap\.exe/ nocase ascii wide
                        $string39 = "zmap -" nocase ascii wide

    condition:
        any of them
}