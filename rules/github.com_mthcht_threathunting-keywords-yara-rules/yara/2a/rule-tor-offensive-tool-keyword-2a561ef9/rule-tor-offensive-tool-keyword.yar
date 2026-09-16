rule rule_tor_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'tor' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tor"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_tor_offensive_tool_keyword = "/bin/torify"
                        $string2_tor_offensive_tool_keyword = /\/dpkg\/info\/tor\.list/
                        $string3_tor_offensive_tool_keyword = /\/etc\/cron\.weekly\/tor/
                        $string4_tor_offensive_tool_keyword = "/etc/default/tor"
                        $string5_tor_offensive_tool_keyword = /\/etc\/init\.d\/tor/
                        $string6_tor_offensive_tool_keyword = "/etc/sv/tor/log"
                        $string7_tor_offensive_tool_keyword = /\/etc\/tor\/.{0,100}\.conf/
                        $string8_tor_offensive_tool_keyword = /\/invocation\:tor\.service/
                        $string9_tor_offensive_tool_keyword = /\/multi\-user\.target\.wants\/tor\.service/
                        $string10_tor_offensive_tool_keyword = /\/proxy\/Tor\.py/
                        $string11_tor_offensive_tool_keyword = /\/proxy\/tor_paths\.py/
                        $string12_tor_offensive_tool_keyword = "/run/tor/socks"
                        $string13_tor_offensive_tool_keyword = /\/run\/tor\/tor\.pid/
                        $string14_tor_offensive_tool_keyword = "/tor -mindepth 1 -maxdepth 1 -type f "
                        $string15_tor_offensive_tool_keyword = "/tor/torrc"
                        $string16_tor_offensive_tool_keyword = "/tor-archive-keyring"
                        $string17_tor_offensive_tool_keyword = /\/tor\-gencert\.exe/
                        $string18_tor_offensive_tool_keyword = /\/tor\-geoipdb\.list/
                        $string19_tor_offensive_tool_keyword = /\/torsocks\.conf/
                        $string20_tor_offensive_tool_keyword = /\/torsocks\.list/
                        $string21_tor_offensive_tool_keyword = "/usr/sbin/tor"
                        $string22_tor_offensive_tool_keyword = "/var/lib/tor/"
                        $string23_tor_offensive_tool_keyword = "/var/log/tor/"
                        $string24_tor_offensive_tool_keyword = /\/win\/Tor\/tor\.exe/ nocase ascii wide
                        $string25_tor_offensive_tool_keyword = /127\.0\.0\.1\:9050/
                        $string26_tor_offensive_tool_keyword = "apt install tor "
                        $string27_tor_offensive_tool_keyword = /deb\.torproject\.org\/torproject\.org\//
                        $string28_tor_offensive_tool_keyword = /deb\.torproject\.org\-keyring/
                        $string29_tor_offensive_tool_keyword = "debian-tor:x"
                        $string30_tor_offensive_tool_keyword = /r0oth3x49\/Tor\.git/
                        $string31_tor_offensive_tool_keyword = /tor\@default\.service/
                        $string32_tor_offensive_tool_keyword = /tor_services\.py/
                        $string33_tor_offensive_tool_keyword = "tor2socks"
                        $string34_tor_offensive_tool_keyword = "tor-geoipdb:all"
                        $string35_tor_offensive_tool_keyword = "tor-geoipdb:amd64"
                        $string36_tor_offensive_tool_keyword = "torify curl "
                        $string37_tor_offensive_tool_keyword = "torify ghaur "
                        $string38_tor_offensive_tool_keyword = "torify nuclei "
                        $string39_tor_offensive_tool_keyword = "torify sqlmap "
                        $string40_tor_offensive_tool_keyword = "TorServiceSetup"
                        $string41_tor_offensive_tool_keyword = "torsocks:amd64"
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