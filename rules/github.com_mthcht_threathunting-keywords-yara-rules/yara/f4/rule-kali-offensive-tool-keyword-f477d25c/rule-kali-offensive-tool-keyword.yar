rule rule_kali_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'kali' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "kali"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_kali_offensive_tool_keyword = " --distribution kali-linux" nocase ascii wide
                        $string2_kali_offensive_tool_keyword = " --unregister Kali-Linux" nocase ascii wide
                        $string3_kali_offensive_tool_keyword = "/#kali-installer-images"
                        $string4_kali_offensive_tool_keyword = "/detail/kali-linux/"
                        $string5_kali_offensive_tool_keyword = "/home/kali"
                        $string6_kali_offensive_tool_keyword = "/kali/pool/main/"
                        $string7_kali_offensive_tool_keyword = "/kali-linux-2023"
                        $string8_kali_offensive_tool_keyword = "/kali-tools-"
                        $string9_kali_offensive_tool_keyword = "/nethunter-images/"
                        $string10_kali_offensive_tool_keyword = "/raw/kali/main/"
                        $string11_kali_offensive_tool_keyword = "/raw/kali/master/"
                        $string12_kali_offensive_tool_keyword = /\\kali\-linux\-2023/
                        $string13_kali_offensive_tool_keyword = /archive\-.{0,100}\.kali\.org\//
                        $string14_kali_offensive_tool_keyword = /cdimage\.kali\.org\//
                        $string15_kali_offensive_tool_keyword = "-d kali-linux "
                        $string16_kali_offensive_tool_keyword = /https\:\/\/gitlab\.com\/kalilinux\//
                        $string17_kali_offensive_tool_keyword = /https\:\/\/kali\.download/
                        $string18_kali_offensive_tool_keyword = /hub\.docker\.com\/u\/kalilinux\//
                        $string19_kali_offensive_tool_keyword = "--install -d kali-linux"
                        $string20_kali_offensive_tool_keyword = /kali\-.{0,100}\.deb/
                        $string21_kali_offensive_tool_keyword = /kali\-linux.{0,100}\.7z/
                        $string22_kali_offensive_tool_keyword = /kali\-linux.{0,100}\.img/
                        $string23_kali_offensive_tool_keyword = /kali\-linux.{0,100}\.iso/
                        $string24_kali_offensive_tool_keyword = /kali\-linux\-.{0,100}\.torrent/
                        $string25_kali_offensive_tool_keyword = /kali\-linux\-.{0,100}\.vmdk/
                        $string26_kali_offensive_tool_keyword = /kali\-linux\-.{0,100}\.vmwarevm/
                        $string27_kali_offensive_tool_keyword = /kali\-linux\-.{0,100}\.vmx/
                        $string28_kali_offensive_tool_keyword = /kali\-linux\-.{0,100}\-installer\-amd64\.iso/
                        $string29_kali_offensive_tool_keyword = /kali\-linux\-.{0,100}\-installer\-everything\-amd64\.iso\.torrent/
                        $string30_kali_offensive_tool_keyword = /kali\-linux\-.{0,100}\-live\-everything\-amd64\.iso\.torrent/
                        $string31_kali_offensive_tool_keyword = /kali\-linux\-.{0,100}\-raspberry\-pi\-armhf\.img\.xz/
                        $string32_kali_offensive_tool_keyword = /kali\-linux\-.{0,100}\-virtualbox\-amd64\.ova/
                        $string33_kali_offensive_tool_keyword = /kali\-linux\-.{0,100}\-vmware\-amd64\.7z/
                        $string34_kali_offensive_tool_keyword = "kalilinux/kali-rolling"
                        $string35_kali_offensive_tool_keyword = /nethunter\-.{0,100}\.torrent/
                        $string36_kali_offensive_tool_keyword = /nethunter\-.{0,100}\.zip/
                        $string37_kali_offensive_tool_keyword = /nethunter\-.{0,100}\-oos\-ten\-kalifs\-full\.zip/
                        $string38_kali_offensive_tool_keyword = "wsl kali-linux"
                        $string39_kali_offensive_tool_keyword = /www\.kali\.org\/get\-kali\//
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