rule rule_dnscrypt_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dnscrypt' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dnscrypt"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_dnscrypt_offensive_tool_keyword = " dnscrypt-proxy" nocase ascii wide
                        $string2_dnscrypt_offensive_tool_keyword = " install dnscrypt-proxy" nocase ascii wide
                        $string3_dnscrypt_offensive_tool_keyword = " restart dnscrypt-proxy" nocase ascii wide
                        $string4_dnscrypt_offensive_tool_keyword = "/dnscrypt-proxy"
                        $string5_dnscrypt_offensive_tool_keyword = /\/dnscrypt\-proxy\.git/ nocase ascii wide
                        $string6_dnscrypt_offensive_tool_keyword = "/opt/dnscrypt-proxy"
                        $string7_dnscrypt_offensive_tool_keyword = /\\dnscrypt\-proxy/ nocase ascii wide
                        $string8_dnscrypt_offensive_tool_keyword = "AgUAAAAAAAAAAAAOZG5zLmdvb2dsZS5jb20NL2V4cGVyaW1lbnRhbA" nocase ascii wide
                        $string9_dnscrypt_offensive_tool_keyword = "DNSCrypt client proxy" nocase ascii wide
                        $string10_dnscrypt_offensive_tool_keyword = "DNSCrypt/dnscrypt-proxy" nocase ascii wide
                        $string11_dnscrypt_offensive_tool_keyword = "dnscrypt-autoinstall" nocase ascii wide
                        $string12_dnscrypt_offensive_tool_keyword = "dnscrypt-proxy -resolve" nocase ascii wide
                        $string13_dnscrypt_offensive_tool_keyword = "dnscrypt-proxy -service" nocase ascii wide
                        $string14_dnscrypt_offensive_tool_keyword = /dnscryptproxy\.exe/ nocase ascii wide
                        $string15_dnscrypt_offensive_tool_keyword = /dnscrypt\-proxy\.exe/ nocase ascii wide
                        $string16_dnscrypt_offensive_tool_keyword = /dnscrypt\-proxy\.socket/ nocase ascii wide
                        $string17_dnscrypt_offensive_tool_keyword = /dnscrypt\-proxy\.toml/ nocase ascii wide
                        $string18_dnscrypt_offensive_tool_keyword = /dnscrypt\-proxy\-android_arm\-.{0,100}\.zip/ nocase ascii wide
                        $string19_dnscrypt_offensive_tool_keyword = /dnscrypt\-proxy\-android_arm64\-.{0,100}\.zip/ nocase ascii wide
                        $string20_dnscrypt_offensive_tool_keyword = /dnscrypt\-proxy\-android_i386\-.{0,100}\.zip/ nocase ascii wide
                        $string21_dnscrypt_offensive_tool_keyword = /dnscrypt\-proxy\-android_x86_64\-.{0,100}\.zip/ nocase ascii wide
                        $string22_dnscrypt_offensive_tool_keyword = /dnscrypt\-proxy\-dragonflybsd_amd64\-.{0,100}\.tar\.gz/ nocase ascii wide
                        $string23_dnscrypt_offensive_tool_keyword = /dnscrypt\-proxy\-freebsd_amd64\-.{0,100}\.tar\.gz/ nocase ascii wide
                        $string24_dnscrypt_offensive_tool_keyword = /dnscrypt\-proxy\-freebsd_arm\-.{0,100}\.tar\.gz/ nocase ascii wide
                        $string25_dnscrypt_offensive_tool_keyword = /dnscrypt\-proxy\-freebsd_i386\-.{0,100}\.tar\.gz/ nocase ascii wide
                        $string26_dnscrypt_offensive_tool_keyword = /dnscrypt\-proxy\-linux_arm\-.{0,100}\.tar\.gz/
                        $string27_dnscrypt_offensive_tool_keyword = /dnscrypt\-proxy\-linux_arm64\-.{0,100}\.tar\.gz/
                        $string28_dnscrypt_offensive_tool_keyword = /dnscrypt\-proxy\-linux_i386\-.{0,100}\.tar\.gz/
                        $string29_dnscrypt_offensive_tool_keyword = /dnscrypt\-proxy\-linux_mips\-.{0,100}\.tar\.gz/
                        $string30_dnscrypt_offensive_tool_keyword = /dnscrypt\-proxy\-linux_mips64\-.{0,100}\.tar\.gz/
                        $string31_dnscrypt_offensive_tool_keyword = /dnscrypt\-proxy\-linux_mips64le\-.{0,100}\.tar\.gz/
                        $string32_dnscrypt_offensive_tool_keyword = /dnscrypt\-proxy\-linux_mipsle\-.{0,100}\.tar\.gz/
                        $string33_dnscrypt_offensive_tool_keyword = /dnscrypt\-proxy\-linux_riscv64\-.{0,100}\.tar\.gz/
                        $string34_dnscrypt_offensive_tool_keyword = /dnscrypt\-proxy\-linux_x86_64\-.{0,100}\.tar\.gz/
                        $string35_dnscrypt_offensive_tool_keyword = /dnscrypt\-proxy\-macos_arm64\-.{0,100}\.zip/ nocase ascii wide
                        $string36_dnscrypt_offensive_tool_keyword = /dnscrypt\-proxy\-macos_x86_64\-.{0,100}\.zip/ nocase ascii wide
                        $string37_dnscrypt_offensive_tool_keyword = "dnscrypt-proxy-master" nocase ascii wide
                        $string38_dnscrypt_offensive_tool_keyword = /dnscrypt\-proxy\-netbsd_amd64\-.{0,100}\.tar\.gz/ nocase ascii wide
                        $string39_dnscrypt_offensive_tool_keyword = /dnscrypt\-proxy\-netbsd_i386\-.{0,100}\.tar\.gz/ nocase ascii wide
                        $string40_dnscrypt_offensive_tool_keyword = /dnscrypt\-proxy\-openbsd_amd64\-.{0,100}\.tar\.gz/ nocase ascii wide
                        $string41_dnscrypt_offensive_tool_keyword = /dnscrypt\-proxy\-openbsd_i386\-.{0,100}\.tar\.gz/ nocase ascii wide
                        $string42_dnscrypt_offensive_tool_keyword = /dnscrypt\-proxy\-solaris_amd64\-.{0,100}\.tar\.gz/ nocase ascii wide
                        $string43_dnscrypt_offensive_tool_keyword = /dnscrypt\-proxy\-win32\-.{0,100}\.zip/ nocase ascii wide
                        $string44_dnscrypt_offensive_tool_keyword = /dnscrypt\-proxy\-win64\-.{0,100}\.zip/ nocase ascii wide
                        $string45_dnscrypt_offensive_tool_keyword = "dnsproxy start scripts" nocase ascii wide
                        $string46_dnscrypt_offensive_tool_keyword = /https\:\/\/127\.0\.0\.1\/dns\-query/ nocase ascii wide
                        $string47_dnscrypt_offensive_tool_keyword = "Thank you for using DNSCrypt-Proxy!" nocase ascii wide
                        $string48_dnscrypt_offensive_tool_keyword = "ubuntu:dnscrypt-msi" nocase ascii wide
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