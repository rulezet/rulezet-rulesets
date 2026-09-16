rule thoth
{
    meta:
        description = "Detection patterns for the tool 'thoth' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "thoth"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-d\s.{0,100}\s\-t\saxfr\s\>/ nocase ascii wide
                        $string2 = /\s\-d\s.{0,100}\s\-t\szonewalk\s\>\s/ nocase ascii wide
                        $string3 = " enum -passive -d " nocase ascii wide
                        $string4 = " -im amass -ir " nocase ascii wide
                        $string5 = " -im get-dns-records" nocase ascii wide
                        $string6 = " -im github-get-repositories" nocase ascii wide
                        $string7 = " -im google-get-linkedIn-employees" nocase ascii wide
                        $string8 = " -im grep-through-commits" nocase ascii wide
                        $string9 = " -im massdns" nocase ascii wide
                        $string10 = " --includeModules amass" nocase ascii wide
                        $string11 = /\sintel\s\-d\s.{0,100}\s\-whois/ nocase ascii wide
                        $string12 = " -rl 4 -ta 8 -t 2100 -an AS8560" nocase ascii wide
                        $string13 = /\/thoth\.git/ nocase ascii wide
                        $string14 = /\/tmp\/amass\.zip/
                        $string15 = "/tmp/bin/csprecon"
                        $string16 = "/tmp/bin/subfinder"
                        $string17 = "/tmp/FavFreak/"
                        $string18 = /\/tmp\/geckodriver\.tar\.gz/
                        $string19 = "/tmp/gitleaks"
                        $string20 = /\/tmp\/scanrepo\.tar\.gz/
                        $string21 = /\/tmp\/truffleHog\.tar\.gz/
                        $string22 = /\|\sfavfreak/ nocase ascii wide
                        $string23 = "amass-get-rootdomains" nocase ascii wide
                        $string24 = "amass-get-subdomains" nocase ascii wide
                        $string25 = "completedns-get-ns-history" nocase ascii wide
                        $string26 = "csprecon -" nocase ascii wide
                        $string27 = "dnslytics-get-rootdomains" nocase ascii wide
                        $string28 = "dnsrecon -" nocase ascii wide
                        $string29 = "dnsrecon-zonetransfer" nocase ascii wide
                        $string30 = "favfreak-http" nocase ascii wide
                        $string31 = /git\slog\s\-p\s\|\sscanrepo\s/ nocase ascii wide
                        $string32 = "gitleaks detect" nocase ascii wide
                        $string33 = "google-get-pdf-metadata " nocase ascii wide
                        $string34 = "google-get-rootdomains " nocase ascii wide
                        $string35 = /grep\-through\-commits\.sh\s/
                        $string36 = "hackertarget-get-rootdomains " nocase ascii wide
                        $string37 = "hakrawler-ip-range" nocase ascii wide
                        $string38 = "handelsregister-get-company-names " nocase ascii wide
                        $string39 = "map-get-tls-alternative-names " nocase ascii wide
                        $string40 = /massdns\s\-r\s.{0,100}\.txt/ nocase ascii wide
                        $string41 = "MattKeeley/Spoofy" nocase ascii wide
                        $string42 = "nmap-reverse-lookup" nocase ascii wide
                        $string43 = "northdata-get-company-names " nocase ascii wide
                        $string44 = "r1cksec/thoth" nocase ascii wide
                        $string45 = "skymem-get-mails " nocase ascii wide
                        $string46 = /Spoofy\/spoofy\.py/ nocase ascii wide
                        $string47 = "spyonweb-get-rootdomains " nocase ascii wide
                        $string48 = /subdomains\-top1million\-110000\.txt/ nocase ascii wide
                        $string49 = "subfinder --silent" nocase ascii wide
                        $string50 = /thoth\.py\s\-/ nocase ascii wide
                        $string51 = /thoth\-master\.zip/ nocase ascii wide
                        $string52 = "tmdb-get-company-names " nocase ascii wide
                        $string53 = "trufflehog git " nocase ascii wide
                        $string54 = "viewdns-get-rootdomains-ip-ns " nocase ascii wide
                        $string55 = "viewdns-get-rootdomains-whois " nocase ascii wide
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