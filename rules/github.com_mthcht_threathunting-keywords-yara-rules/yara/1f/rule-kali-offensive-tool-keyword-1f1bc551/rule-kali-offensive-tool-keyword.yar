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
                        $string13_kali_offensive_tool_keyword = /archive\-.{0,1000}\.kali\.org\//
                        $string14_kali_offensive_tool_keyword = /cdimage\.kali\.org\//
                        $string15_kali_offensive_tool_keyword = "-d kali-linux "
                        $string16_kali_offensive_tool_keyword = /https\:\/\/gitlab\.com\/kalilinux\//
                        $string17_kali_offensive_tool_keyword = /https\:\/\/kali\.download/
                        $string18_kali_offensive_tool_keyword = /hub\.docker\.com\/u\/kalilinux\//
                        $string19_kali_offensive_tool_keyword = "--install -d kali-linux"
                        $string20_kali_offensive_tool_keyword = /kali\-.{0,1000}\.deb/
                        $string21_kali_offensive_tool_keyword = /kali\-linux.{0,1000}\.7z/
                        $string22_kali_offensive_tool_keyword = /kali\-linux.{0,1000}\.img/
                        $string23_kali_offensive_tool_keyword = /kali\-linux.{0,1000}\.iso/
                        $string24_kali_offensive_tool_keyword = /kali\-linux\-.{0,1000}\.torrent/
                        $string25_kali_offensive_tool_keyword = /kali\-linux\-.{0,1000}\.vmdk/
                        $string26_kali_offensive_tool_keyword = /kali\-linux\-.{0,1000}\.vmwarevm/
                        $string27_kali_offensive_tool_keyword = /kali\-linux\-.{0,1000}\.vmx/
                        $string28_kali_offensive_tool_keyword = /kali\-linux\-.{0,1000}\-installer\-amd64\.iso/
                        $string29_kali_offensive_tool_keyword = /kali\-linux\-.{0,1000}\-installer\-everything\-amd64\.iso\.torrent/
                        $string30_kali_offensive_tool_keyword = /kali\-linux\-.{0,1000}\-live\-everything\-amd64\.iso\.torrent/
                        $string31_kali_offensive_tool_keyword = /kali\-linux\-.{0,1000}\-raspberry\-pi\-armhf\.img\.xz/
                        $string32_kali_offensive_tool_keyword = /kali\-linux\-.{0,1000}\-virtualbox\-amd64\.ova/
                        $string33_kali_offensive_tool_keyword = /kali\-linux\-.{0,1000}\-vmware\-amd64\.7z/
                        $string34_kali_offensive_tool_keyword = "kalilinux/kali-rolling"
                        $string35_kali_offensive_tool_keyword = /nethunter\-.{0,1000}\.torrent/
                        $string36_kali_offensive_tool_keyword = /nethunter\-.{0,1000}\.zip/
                        $string37_kali_offensive_tool_keyword = /nethunter\-.{0,1000}\-oos\-ten\-kalifs\-full\.zip/
                        $string38_kali_offensive_tool_keyword = "wsl kali-linux"
                        $string39_kali_offensive_tool_keyword = /www\.kali\.org\/get\-kali\//

    condition:
        any of them
}