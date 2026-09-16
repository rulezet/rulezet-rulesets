rule rule_blackarch_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'blackarch' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "blackarch"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_blackarch_offensive_tool_keyword = "/tmp/blackarch" nocase ascii wide
                        $string2_blackarch_offensive_tool_keyword = /au\.mirrors\.cicku\.me\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string3_blackarch_offensive_tool_keyword = /blackarch\.cs\.nycu\.edu\.tw\/.{0,100}\/os\// nocase ascii wide
                        $string4_blackarch_offensive_tool_keyword = /blackarch\.leneveu\.fr\/.{0,100}\/os\// nocase ascii wide
                        $string5_blackarch_offensive_tool_keyword = /blackarch\.mirror\.digitalpacific\.com\.au\/.{0,100}\/os\// nocase ascii wide
                        $string6_blackarch_offensive_tool_keyword = /blackarch\.mirror\.garr\.it\/mirrors\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string7_blackarch_offensive_tool_keyword = /blackarch\.org\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string8_blackarch_offensive_tool_keyword = /blackarch\.org\/blackarch\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string9_blackarch_offensive_tool_keyword = /blackarch\.unixpeople\.org\/.{0,100}\/os\// nocase ascii wide
                        $string10_blackarch_offensive_tool_keyword = /ca\.mirrors\.cicku\.me\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string11_blackarch_offensive_tool_keyword = /de\.mirrors\.cicku\.me\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string12_blackarch_offensive_tool_keyword = /distro\.ibiblio\.org\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string13_blackarch_offensive_tool_keyword = /download\.nus\.edu\.sg\/mirror\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string14_blackarch_offensive_tool_keyword = /eu\.mirrors\.cicku\.me\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string15_blackarch_offensive_tool_keyword = /ftp\.cc\.uoc\.gr\/mirrors\/linux\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string16_blackarch_offensive_tool_keyword = /ftp\.halifax\.rwth\-aachen\.de\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string17_blackarch_offensive_tool_keyword = /ftp\.icm\.edu\.pl\/pub\/Linux\/dist\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string18_blackarch_offensive_tool_keyword = /ftp\.kddilabs\.jp\/Linux\/packages\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string19_blackarch_offensive_tool_keyword = /ftp\.linux\.org\.tr\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string20_blackarch_offensive_tool_keyword = /http\:\/\/mirror\.archlinux\.no/ nocase ascii wide
                        $string21_blackarch_offensive_tool_keyword = /https\:\/\/raw\.githubusercontent\.com\/BlackArch\/blackarch\/master\/mirror\/mirror\.lst/ nocase ascii wide
                        $string22_blackarch_offensive_tool_keyword = /https\:\/\/www\.blackarch\.org\/blackarch\/blackarch\/lastupdate/ nocase ascii wide
                        $string23_blackarch_offensive_tool_keyword = /in\.mirrors\.cicku\.me\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string24_blackarch_offensive_tool_keyword = /jp\.mirrors\.cicku\.me\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string25_blackarch_offensive_tool_keyword = /kr\.mirrors\.cicku\.me\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string26_blackarch_offensive_tool_keyword = /md\.mirrors\.hacktegic\.com\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string27_blackarch_offensive_tool_keyword = /mirror\.archlinux\.tw\/BlackArch\/.{0,100}\/os\// nocase ascii wide
                        $string28_blackarch_offensive_tool_keyword = /mirror\.cedia\.org\.ec\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string29_blackarch_offensive_tool_keyword = /mirror\.cyberbits\.eu\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string30_blackarch_offensive_tool_keyword = /mirror\.easyname\.at\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string31_blackarch_offensive_tool_keyword = /mirror\.easyname\.ch\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string32_blackarch_offensive_tool_keyword = /mirror\.maa\.albony\.in\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string33_blackarch_offensive_tool_keyword = /mirror\.math\.princeton\.edu\/pub\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string34_blackarch_offensive_tool_keyword = /mirror\.serverion\.com\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string35_blackarch_offensive_tool_keyword = /mirror\.sg\.gs\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string36_blackarch_offensive_tool_keyword = /mirror\.sjtu\.edu\.cn\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string37_blackarch_offensive_tool_keyword = /mirror\.team\-cymru\.com\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string38_blackarch_offensive_tool_keyword = /mirror\.telepoint\.bg\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string39_blackarch_offensive_tool_keyword = /mirror\.tillo\.ch\/ftp\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string40_blackarch_offensive_tool_keyword = /mirror\.yandex\.ru\/mirrors\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string41_blackarch_offensive_tool_keyword = /mirror\.zetup\.net\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string42_blackarch_offensive_tool_keyword = /mirrors\.aliyun\.com\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string43_blackarch_offensive_tool_keyword = /mirrors\.cicku\.me\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string44_blackarch_offensive_tool_keyword = /mirrors\.dotsrc\.org\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string45_blackarch_offensive_tool_keyword = /mirrors\.gethosted\.online\/blackarch\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string46_blackarch_offensive_tool_keyword = /mirrors\.hostico\.ro\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string47_blackarch_offensive_tool_keyword = /mirrors\.hust\.edu\.cn\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string48_blackarch_offensive_tool_keyword = /mirrors\.nju\.edu\.cn\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string49_blackarch_offensive_tool_keyword = /mirrors\.ocf\.berkeley\.edu\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string50_blackarch_offensive_tool_keyword = /mirrors\.tuna\.tsinghua\.edu\.cn\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string51_blackarch_offensive_tool_keyword = /mirrors\.ustc\.edu\.cn\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string52_blackarch_offensive_tool_keyword = /quantum\-mirror\.hu\/mirrors\/pub\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string53_blackarch_offensive_tool_keyword = /repository\.su\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string54_blackarch_offensive_tool_keyword = /sg\.mirrors\.cicku\.me\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string55_blackarch_offensive_tool_keyword = /us\.mirrors\.cicku\.me\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string56_blackarch_offensive_tool_keyword = /www\.ftp\.ne\.jp\/Linux\/packages\/blackarch\/.{0,100}\/os\// nocase ascii wide
                        $string57_blackarch_offensive_tool_keyword = /www\.mirrorservice\.org\/sites\/blackarch\.org\/blackarch\/.{0,100}\/os\// nocase ascii wide
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