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
                        $string13 = /archive\-.{0,1000}\.kali\.org\//
                        $string14 = /cdimage\.kali\.org\//
                        $string15 = "-d kali-linux "
                        $string16 = /https\:\/\/gitlab\.com\/kalilinux\//
                        $string17 = /https\:\/\/kali\.download/
                        $string18 = /hub\.docker\.com\/u\/kalilinux\//
                        $string19 = "--install -d kali-linux"
                        $string20 = /kali\-.{0,1000}\.deb/
                        $string21 = /kali\-linux.{0,1000}\.7z/
                        $string22 = /kali\-linux.{0,1000}\.img/
                        $string23 = /kali\-linux.{0,1000}\.iso/
                        $string24 = /kali\-linux\-.{0,1000}\.torrent/
                        $string25 = /kali\-linux\-.{0,1000}\.vmdk/
                        $string26 = /kali\-linux\-.{0,1000}\.vmwarevm/
                        $string27 = /kali\-linux\-.{0,1000}\.vmx/
                        $string28 = /kali\-linux\-.{0,1000}\-installer\-amd64\.iso/
                        $string29 = /kali\-linux\-.{0,1000}\-installer\-everything\-amd64\.iso\.torrent/
                        $string30 = /kali\-linux\-.{0,1000}\-live\-everything\-amd64\.iso\.torrent/
                        $string31 = /kali\-linux\-.{0,1000}\-raspberry\-pi\-armhf\.img\.xz/
                        $string32 = /kali\-linux\-.{0,1000}\-virtualbox\-amd64\.ova/
                        $string33 = /kali\-linux\-.{0,1000}\-vmware\-amd64\.7z/
                        $string34 = "kalilinux/kali-rolling"
                        $string35 = /nethunter\-.{0,1000}\.torrent/
                        $string36 = /nethunter\-.{0,1000}\.zip/
                        $string37 = /nethunter\-.{0,1000}\-oos\-ten\-kalifs\-full\.zip/
                        $string38 = "wsl kali-linux"
                        $string39 = /www\.kali\.org\/get\-kali\//

    condition:
        any of them
}