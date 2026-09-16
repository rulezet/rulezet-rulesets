rule rule_scan4all_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'scan4all' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "scan4all"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_scan4all_offensive_tool_keyword = /\s\-l\snmapRssuilt\.xml\s\-v/ nocase ascii wide
                        $string2_scan4all_offensive_tool_keyword = /\.\/scan4all\s/
                        $string3_scan4all_offensive_tool_keyword = /\.\/scan4all/
                        $string4_scan4all_offensive_tool_keyword = /\/config\/doNmapScanWin\.bat\s/ nocase ascii wide
                        $string5_scan4all_offensive_tool_keyword = /\/CVE\-.{0,1000}\-.{0,1000}_POC\.py/
                        $string6_scan4all_offensive_tool_keyword = /\/CVE\-2022\-.{0,1000}\.go/
                        $string7_scan4all_offensive_tool_keyword = /\/dicts\/ftp_default\.txt/ nocase ascii wide
                        $string8_scan4all_offensive_tool_keyword = /\/scan4all\.exe/ nocase ascii wide
                        $string9_scan4all_offensive_tool_keyword = /\/scan4all\.git/ nocase ascii wide
                        $string10_scan4all_offensive_tool_keyword = /\/scan4all\.git/ nocase ascii wide
                        $string11_scan4all_offensive_tool_keyword = /\/scan4all\.rb/ nocase ascii wide
                        $string12_scan4all_offensive_tool_keyword = "/scan4all/lib/api" nocase ascii wide
                        $string13_scan4all_offensive_tool_keyword = "/scan4all/lib/util" nocase ascii wide
                        $string14_scan4all_offensive_tool_keyword = /\\scan4all\.exe/ nocase ascii wide
                        $string15_scan4all_offensive_tool_keyword = /\\scan4all\-main/ nocase ascii wide
                        $string16_scan4all_offensive_tool_keyword = /async_webshell\-all\.py/ nocase ascii wide
                        $string17_scan4all_offensive_tool_keyword = "config/51pwn/CVE-" nocase ascii wide
                        $string18_scan4all_offensive_tool_keyword = /dicts\/ftp_pswd\.txt/ nocase ascii wide
                        $string19_scan4all_offensive_tool_keyword = /dicts\/ssh_default\.txt/ nocase ascii wide
                        $string20_scan4all_offensive_tool_keyword = /dicts\/ssh_pswd\.txt/ nocase ascii wide
                        $string21_scan4all_offensive_tool_keyword = "hktalent/scan4all" nocase ascii wide
                        $string22_scan4all_offensive_tool_keyword = "hktalent/scan4all" nocase ascii wide
                        $string23_scan4all_offensive_tool_keyword = /pocs_go\/.{0,1000}\/CVE\-.{0,1000}\.go/ nocase ascii wide
                        $string24_scan4all_offensive_tool_keyword = "scan4all -" nocase ascii wide
                        $string25_scan4all_offensive_tool_keyword = /scan4all\s\-.{0,1000}\.xml/ nocase ascii wide
                        $string26_scan4all_offensive_tool_keyword = "scan4all -h" nocase ascii wide
                        $string27_scan4all_offensive_tool_keyword = "scan4all -tp " nocase ascii wide
                        $string28_scan4all_offensive_tool_keyword = /scan4all\.51pwn\.com/ nocase ascii wide
                        $string29_scan4all_offensive_tool_keyword = /scan4all\.51pwn\.com\// nocase ascii wide
                        $string30_scan4all_offensive_tool_keyword = /scan4all_.{0,1000}\..{0,1000}_linux_amd64\.zip/
                        $string31_scan4all_offensive_tool_keyword = /scan4all_.{0,1000}\..{0,1000}_macOS_amd64\.zip/ nocase ascii wide
                        $string32_scan4all_offensive_tool_keyword = /scan4all_.{0,1000}\..{0,1000}_macOS_arm64\.zip/ nocase ascii wide
                        $string33_scan4all_offensive_tool_keyword = /scan4all_.{0,1000}\..{0,1000}_windows_amd64\.zip/ nocase ascii wide
                        $string34_scan4all_offensive_tool_keyword = /scan4all_.{0,1000}_linux_amd64\.zip/
                        $string35_scan4all_offensive_tool_keyword = /scan4all_.{0,1000}_windows_amd64\.zip/ nocase ascii wide
                        $string36_scan4all_offensive_tool_keyword = /scan4all_windows_386\.exe/ nocase ascii wide
                        $string37_scan4all_offensive_tool_keyword = /scan4all_windows_amd64\.exe/ nocase ascii wide
                        $string38_scan4all_offensive_tool_keyword = "scan4all-main" nocase ascii wide

    condition:
        any of them
}