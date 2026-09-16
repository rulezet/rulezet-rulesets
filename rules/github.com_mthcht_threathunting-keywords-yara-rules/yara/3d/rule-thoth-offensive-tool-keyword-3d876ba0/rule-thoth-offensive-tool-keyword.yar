rule rule_thoth_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'thoth' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "thoth"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_thoth_offensive_tool_keyword = /\s\-d\s.{0,1000}\s\-t\saxfr\s\>/ nocase ascii wide
                        $string2_thoth_offensive_tool_keyword = /\s\-d\s.{0,1000}\s\-t\szonewalk\s\>\s/ nocase ascii wide
                        $string3_thoth_offensive_tool_keyword = " enum -passive -d " nocase ascii wide
                        $string4_thoth_offensive_tool_keyword = " -im amass -ir " nocase ascii wide
                        $string5_thoth_offensive_tool_keyword = " -im get-dns-records" nocase ascii wide
                        $string6_thoth_offensive_tool_keyword = " -im github-get-repositories" nocase ascii wide
                        $string7_thoth_offensive_tool_keyword = " -im google-get-linkedIn-employees" nocase ascii wide
                        $string8_thoth_offensive_tool_keyword = " -im grep-through-commits" nocase ascii wide
                        $string9_thoth_offensive_tool_keyword = " -im massdns" nocase ascii wide
                        $string10_thoth_offensive_tool_keyword = " --includeModules amass" nocase ascii wide
                        $string11_thoth_offensive_tool_keyword = /\sintel\s\-d\s.{0,1000}\s\-whois/ nocase ascii wide
                        $string12_thoth_offensive_tool_keyword = " -rl 4 -ta 8 -t 2100 -an AS8560" nocase ascii wide
                        $string13_thoth_offensive_tool_keyword = /\/thoth\.git/ nocase ascii wide
                        $string14_thoth_offensive_tool_keyword = /\/tmp\/amass\.zip/
                        $string15_thoth_offensive_tool_keyword = "/tmp/bin/csprecon"
                        $string16_thoth_offensive_tool_keyword = "/tmp/bin/subfinder"
                        $string17_thoth_offensive_tool_keyword = "/tmp/FavFreak/"
                        $string18_thoth_offensive_tool_keyword = /\/tmp\/geckodriver\.tar\.gz/
                        $string19_thoth_offensive_tool_keyword = "/tmp/gitleaks"
                        $string20_thoth_offensive_tool_keyword = /\/tmp\/scanrepo\.tar\.gz/
                        $string21_thoth_offensive_tool_keyword = /\/tmp\/truffleHog\.tar\.gz/
                        $string22_thoth_offensive_tool_keyword = /\|\sfavfreak/ nocase ascii wide
                        $string23_thoth_offensive_tool_keyword = "amass-get-rootdomains" nocase ascii wide
                        $string24_thoth_offensive_tool_keyword = "amass-get-subdomains" nocase ascii wide
                        $string25_thoth_offensive_tool_keyword = "completedns-get-ns-history" nocase ascii wide
                        $string26_thoth_offensive_tool_keyword = "csprecon -" nocase ascii wide
                        $string27_thoth_offensive_tool_keyword = "dnslytics-get-rootdomains" nocase ascii wide
                        $string28_thoth_offensive_tool_keyword = "dnsrecon -" nocase ascii wide
                        $string29_thoth_offensive_tool_keyword = "dnsrecon-zonetransfer" nocase ascii wide
                        $string30_thoth_offensive_tool_keyword = "favfreak-http" nocase ascii wide
                        $string31_thoth_offensive_tool_keyword = /git\slog\s\-p\s\|\sscanrepo\s/ nocase ascii wide
                        $string32_thoth_offensive_tool_keyword = "gitleaks detect" nocase ascii wide
                        $string33_thoth_offensive_tool_keyword = "google-get-pdf-metadata " nocase ascii wide
                        $string34_thoth_offensive_tool_keyword = "google-get-rootdomains " nocase ascii wide
                        $string35_thoth_offensive_tool_keyword = /grep\-through\-commits\.sh\s/
                        $string36_thoth_offensive_tool_keyword = "hackertarget-get-rootdomains " nocase ascii wide
                        $string37_thoth_offensive_tool_keyword = "hakrawler-ip-range" nocase ascii wide
                        $string38_thoth_offensive_tool_keyword = "handelsregister-get-company-names " nocase ascii wide
                        $string39_thoth_offensive_tool_keyword = "map-get-tls-alternative-names " nocase ascii wide
                        $string40_thoth_offensive_tool_keyword = /massdns\s\-r\s.{0,1000}\.txt/ nocase ascii wide
                        $string41_thoth_offensive_tool_keyword = "MattKeeley/Spoofy" nocase ascii wide
                        $string42_thoth_offensive_tool_keyword = "nmap-reverse-lookup" nocase ascii wide
                        $string43_thoth_offensive_tool_keyword = "northdata-get-company-names " nocase ascii wide
                        $string44_thoth_offensive_tool_keyword = "r1cksec/thoth" nocase ascii wide
                        $string45_thoth_offensive_tool_keyword = "skymem-get-mails " nocase ascii wide
                        $string46_thoth_offensive_tool_keyword = /Spoofy\/spoofy\.py/ nocase ascii wide
                        $string47_thoth_offensive_tool_keyword = "spyonweb-get-rootdomains " nocase ascii wide
                        $string48_thoth_offensive_tool_keyword = /subdomains\-top1million\-110000\.txt/ nocase ascii wide
                        $string49_thoth_offensive_tool_keyword = "subfinder --silent" nocase ascii wide
                        $string50_thoth_offensive_tool_keyword = /thoth\.py\s\-/ nocase ascii wide
                        $string51_thoth_offensive_tool_keyword = /thoth\-master\.zip/ nocase ascii wide
                        $string52_thoth_offensive_tool_keyword = "tmdb-get-company-names " nocase ascii wide
                        $string53_thoth_offensive_tool_keyword = "trufflehog git " nocase ascii wide
                        $string54_thoth_offensive_tool_keyword = "viewdns-get-rootdomains-ip-ns " nocase ascii wide
                        $string55_thoth_offensive_tool_keyword = "viewdns-get-rootdomains-whois " nocase ascii wide

    condition:
        any of them
}