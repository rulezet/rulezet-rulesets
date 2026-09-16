rule kali
{
    meta:
        description = "Detection patterns for the tool 'kali' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "kali"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " --distribution kali-linux" nocase ascii wide
                        $string2 = " --unregister Kali-Linux" nocase ascii wide
                        $string3 = "/#kali-installer-images"
                        $string4 = "/detail/kali-linux/"
                        $string5 = "/home/kali"
                        $string6 = "/kali/pool/main/"
                        $string7 = "/kali-linux-2023"
                        $string8 = "/kali-tools-"
                        $string9 = "/nethunter-images/"
                        $string10 = "/raw/kali/main/"
                        $string11 = "/raw/kali/master/"
                        $string12 = /\\kali\-linux\-2023/
                        $string13 = /archive\-.{0,100}\.kali\.org\//
                        $string14 = /cdimage\.kali\.org\//
                        $string15 = "-d kali-linux "
                        $string16 = /https\:\/\/gitlab\.com\/kalilinux\//
                        $string17 = /https\:\/\/kali\.download/
                        $string18 = /hub\.docker\.com\/u\/kalilinux\//
                        $string19 = "--install -d kali-linux"
                        $string20 = /kali\-.{0,100}\.deb/
                        $string21 = /kali\-linux.{0,100}\.7z/
                        $string22 = /kali\-linux.{0,100}\.img/
                        $string23 = /kali\-linux.{0,100}\.iso/
                        $string24 = /kali\-linux\-.{0,100}\.torrent/
                        $string25 = /kali\-linux\-.{0,100}\.vmdk/
                        $string26 = /kali\-linux\-.{0,100}\.vmwarevm/
                        $string27 = /kali\-linux\-.{0,100}\.vmx/
                        $string28 = /kali\-linux\-.{0,100}\-installer\-amd64\.iso/
                        $string29 = /kali\-linux\-.{0,100}\-installer\-everything\-amd64\.iso\.torrent/
                        $string30 = /kali\-linux\-.{0,100}\-live\-everything\-amd64\.iso\.torrent/
                        $string31 = /kali\-linux\-.{0,100}\-raspberry\-pi\-armhf\.img\.xz/
                        $string32 = /kali\-linux\-.{0,100}\-virtualbox\-amd64\.ova/
                        $string33 = /kali\-linux\-.{0,100}\-vmware\-amd64\.7z/
                        $string34 = "kalilinux/kali-rolling"
                        $string35 = /nethunter\-.{0,100}\.torrent/
                        $string36 = /nethunter\-.{0,100}\.zip/
                        $string37 = /nethunter\-.{0,100}\-oos\-ten\-kalifs\-full\.zip/
                        $string38 = "wsl kali-linux"
                        $string39 = /www\.kali\.org\/get\-kali\//
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