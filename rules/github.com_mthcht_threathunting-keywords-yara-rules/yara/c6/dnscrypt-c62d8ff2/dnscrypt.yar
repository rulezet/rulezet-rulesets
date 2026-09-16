rule dnscrypt
{
    meta:
        description = "Detection patterns for the tool 'dnscrypt' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dnscrypt"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " dnscrypt-proxy" nocase ascii wide
                        $string2 = " install dnscrypt-proxy" nocase ascii wide
                        $string3 = " restart dnscrypt-proxy" nocase ascii wide
                        $string4 = "/dnscrypt-proxy"
                        $string5 = /\/dnscrypt\-proxy\.git/ nocase ascii wide
                        $string6 = "/opt/dnscrypt-proxy"
                        $string7 = /\\dnscrypt\-proxy/ nocase ascii wide
                        $string8 = "AgUAAAAAAAAAAAAOZG5zLmdvb2dsZS5jb20NL2V4cGVyaW1lbnRhbA" nocase ascii wide
                        $string9 = "DNSCrypt client proxy" nocase ascii wide
                        $string10 = "DNSCrypt/dnscrypt-proxy" nocase ascii wide
                        $string11 = "dnscrypt-autoinstall" nocase ascii wide
                        $string12 = "dnscrypt-proxy -resolve" nocase ascii wide
                        $string13 = "dnscrypt-proxy -service" nocase ascii wide
                        $string14 = /dnscryptproxy\.exe/ nocase ascii wide
                        $string15 = /dnscrypt\-proxy\.exe/ nocase ascii wide
                        $string16 = /dnscrypt\-proxy\.socket/ nocase ascii wide
                        $string17 = /dnscrypt\-proxy\.toml/ nocase ascii wide
                        $string18 = /dnscrypt\-proxy\-android_arm\-.{0,100}\.zip/ nocase ascii wide
                        $string19 = /dnscrypt\-proxy\-android_arm64\-.{0,100}\.zip/ nocase ascii wide
                        $string20 = /dnscrypt\-proxy\-android_i386\-.{0,100}\.zip/ nocase ascii wide
                        $string21 = /dnscrypt\-proxy\-android_x86_64\-.{0,100}\.zip/ nocase ascii wide
                        $string22 = /dnscrypt\-proxy\-dragonflybsd_amd64\-.{0,100}\.tar\.gz/ nocase ascii wide
                        $string23 = /dnscrypt\-proxy\-freebsd_amd64\-.{0,100}\.tar\.gz/ nocase ascii wide
                        $string24 = /dnscrypt\-proxy\-freebsd_arm\-.{0,100}\.tar\.gz/ nocase ascii wide
                        $string25 = /dnscrypt\-proxy\-freebsd_i386\-.{0,100}\.tar\.gz/ nocase ascii wide
                        $string26 = /dnscrypt\-proxy\-linux_arm\-.{0,100}\.tar\.gz/
                        $string27 = /dnscrypt\-proxy\-linux_arm64\-.{0,100}\.tar\.gz/
                        $string28 = /dnscrypt\-proxy\-linux_i386\-.{0,100}\.tar\.gz/
                        $string29 = /dnscrypt\-proxy\-linux_mips\-.{0,100}\.tar\.gz/
                        $string30 = /dnscrypt\-proxy\-linux_mips64\-.{0,100}\.tar\.gz/
                        $string31 = /dnscrypt\-proxy\-linux_mips64le\-.{0,100}\.tar\.gz/
                        $string32 = /dnscrypt\-proxy\-linux_mipsle\-.{0,100}\.tar\.gz/
                        $string33 = /dnscrypt\-proxy\-linux_riscv64\-.{0,100}\.tar\.gz/
                        $string34 = /dnscrypt\-proxy\-linux_x86_64\-.{0,100}\.tar\.gz/
                        $string35 = /dnscrypt\-proxy\-macos_arm64\-.{0,100}\.zip/ nocase ascii wide
                        $string36 = /dnscrypt\-proxy\-macos_x86_64\-.{0,100}\.zip/ nocase ascii wide
                        $string37 = "dnscrypt-proxy-master" nocase ascii wide
                        $string38 = /dnscrypt\-proxy\-netbsd_amd64\-.{0,100}\.tar\.gz/ nocase ascii wide
                        $string39 = /dnscrypt\-proxy\-netbsd_i386\-.{0,100}\.tar\.gz/ nocase ascii wide
                        $string40 = /dnscrypt\-proxy\-openbsd_amd64\-.{0,100}\.tar\.gz/ nocase ascii wide
                        $string41 = /dnscrypt\-proxy\-openbsd_i386\-.{0,100}\.tar\.gz/ nocase ascii wide
                        $string42 = /dnscrypt\-proxy\-solaris_amd64\-.{0,100}\.tar\.gz/ nocase ascii wide
                        $string43 = /dnscrypt\-proxy\-win32\-.{0,100}\.zip/ nocase ascii wide
                        $string44 = /dnscrypt\-proxy\-win64\-.{0,100}\.zip/ nocase ascii wide
                        $string45 = "dnsproxy start scripts" nocase ascii wide
                        $string46 = /https\:\/\/127\.0\.0\.1\/dns\-query/ nocase ascii wide
                        $string47 = "Thank you for using DNSCrypt-Proxy!" nocase ascii wide
                        $string48 = "ubuntu:dnscrypt-msi" nocase ascii wide
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