rule bettercap
{
    meta:
        description = "Detection patterns for the tool 'bettercap' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bettercap"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " bettercap"
                        $string2 = /\s\-caplet\s.{0,1000}\.cap/
                        $string3 = /\s\-eval\s.{0,1000}caplets\.update.{0,1000}\sui\.update/
                        $string4 = "/arp_spoof/"
                        $string5 = "/bettercap"
                        $string6 = /\/c2\/c2\.go/
                        $string7 = /\/dns_grabber\./
                        $string8 = "/dns_spoof"
                        $string9 = /\/hid_inject\./
                        $string10 = /\/hid_sniff\./
                        $string11 = "/ndp_spoof"
                        $string12 = "/net_recon/"
                        $string13 = /\/net_sniff\./
                        $string14 = /\/net_sniff_.{0,1000}\./
                        $string15 = /\/wifi_hopping\./
                        $string16 = /arp\.spoof\son/
                        $string17 = /arp\.spoof\./
                        $string18 = /arp\.spoof\.targets/
                        $string19 = /arp_spoof\./
                        $string20 = "ArpSpoofer"
                        $string21 = "bettercap "
                        $string22 = /bettercap\./
                        $string23 = /bettercap_\.deb/
                        $string24 = /bettercap\-master\.zip/
                        $string25 = /ble_recon\.go/
                        $string26 = /dhcp6\.spoof\./
                        $string27 = /dns\.spoof\son/
                        $string28 = /dns\.spoof\.address/
                        $string29 = /dns\.spoof\.all/
                        $string30 = /dns\.spoof\.domains/
                        $string31 = /dns\.spoof\.hosts/
                        $string32 = /dns_spoof\./
                        $string33 = /mac\.changer\son/
                        $string34 = /ndp_spoof\./
                        $string35 = /net\.fuzz\s/
                        $string36 = /net\.fuzz\./
                        $string37 = /net\.probe\son/
                        $string38 = /net\.probe\son/
                        $string39 = /net\.sniff\s/
                        $string40 = /net\.sniff\./
                        $string41 = /net_recon\./
                        $string42 = /wifi_fake_auth\./
                        $string43 = "wifi_recon_handshakes"
                        $string44 = /net\.recon\s/

    condition:
        any of them
}