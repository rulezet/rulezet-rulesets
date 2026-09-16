rule scan4all
{
    meta:
        description = "Detection patterns for the tool 'scan4all' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "scan4all"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-l\snmapRssuilt\.xml\s\-v/ nocase ascii wide
                        $string2 = /\.\/scan4all\s/
                        $string3 = /\.\/scan4all/
                        $string4 = /\/config\/doNmapScanWin\.bat\s/ nocase ascii wide
                        $string5 = /\/CVE\-.{0,1000}\-.{0,1000}_POC\.py/
                        $string6 = /\/CVE\-2022\-.{0,1000}\.go/
                        $string7 = /\/dicts\/ftp_default\.txt/ nocase ascii wide
                        $string8 = /\/scan4all\.exe/ nocase ascii wide
                        $string9 = /\/scan4all\.git/ nocase ascii wide
                        $string10 = /\/scan4all\.git/ nocase ascii wide
                        $string11 = /\/scan4all\.rb/ nocase ascii wide
                        $string12 = "/scan4all/lib/api" nocase ascii wide
                        $string13 = "/scan4all/lib/util" nocase ascii wide
                        $string14 = /\\scan4all\.exe/ nocase ascii wide
                        $string15 = /\\scan4all\-main/ nocase ascii wide
                        $string16 = /async_webshell\-all\.py/ nocase ascii wide
                        $string17 = "config/51pwn/CVE-" nocase ascii wide
                        $string18 = /dicts\/ftp_pswd\.txt/ nocase ascii wide
                        $string19 = /dicts\/ssh_default\.txt/ nocase ascii wide
                        $string20 = /dicts\/ssh_pswd\.txt/ nocase ascii wide
                        $string21 = "hktalent/scan4all" nocase ascii wide
                        $string22 = "hktalent/scan4all" nocase ascii wide
                        $string23 = /pocs_go\/.{0,1000}\/CVE\-.{0,1000}\.go/ nocase ascii wide
                        $string24 = "scan4all -" nocase ascii wide
                        $string25 = /scan4all\s\-.{0,1000}\.xml/ nocase ascii wide
                        $string26 = "scan4all -h" nocase ascii wide
                        $string27 = "scan4all -tp " nocase ascii wide
                        $string28 = /scan4all\.51pwn\.com/ nocase ascii wide
                        $string29 = /scan4all\.51pwn\.com\// nocase ascii wide
                        $string30 = /scan4all_.{0,1000}\..{0,1000}_linux_amd64\.zip/
                        $string31 = /scan4all_.{0,1000}\..{0,1000}_macOS_amd64\.zip/ nocase ascii wide
                        $string32 = /scan4all_.{0,1000}\..{0,1000}_macOS_arm64\.zip/ nocase ascii wide
                        $string33 = /scan4all_.{0,1000}\..{0,1000}_windows_amd64\.zip/ nocase ascii wide
                        $string34 = /scan4all_.{0,1000}_linux_amd64\.zip/
                        $string35 = /scan4all_.{0,1000}_windows_amd64\.zip/ nocase ascii wide
                        $string36 = /scan4all_windows_386\.exe/ nocase ascii wide
                        $string37 = /scan4all_windows_amd64\.exe/ nocase ascii wide
                        $string38 = "scan4all-main" nocase ascii wide

    condition:
        any of them
}