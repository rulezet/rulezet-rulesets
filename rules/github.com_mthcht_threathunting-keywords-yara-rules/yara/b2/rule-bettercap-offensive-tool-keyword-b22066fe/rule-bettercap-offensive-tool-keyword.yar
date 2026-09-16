rule rule_bettercap_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'bettercap' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bettercap"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_bettercap_offensive_tool_keyword = " bettercap"
                        $string2_bettercap_offensive_tool_keyword = /\s\-caplet\s.{0,1000}\.cap/
                        $string3_bettercap_offensive_tool_keyword = /\s\-eval\s.{0,1000}caplets\.update.{0,1000}\sui\.update/
                        $string4_bettercap_offensive_tool_keyword = "/arp_spoof/"
                        $string5_bettercap_offensive_tool_keyword = "/bettercap"
                        $string6_bettercap_offensive_tool_keyword = /\/c2\/c2\.go/
                        $string7_bettercap_offensive_tool_keyword = /\/dns_grabber\./
                        $string8_bettercap_offensive_tool_keyword = "/dns_spoof"
                        $string9_bettercap_offensive_tool_keyword = /\/hid_inject\./
                        $string10_bettercap_offensive_tool_keyword = /\/hid_sniff\./
                        $string11_bettercap_offensive_tool_keyword = "/ndp_spoof"
                        $string12_bettercap_offensive_tool_keyword = "/net_recon/"
                        $string13_bettercap_offensive_tool_keyword = /\/net_sniff\./
                        $string14_bettercap_offensive_tool_keyword = /\/net_sniff_.{0,1000}\./
                        $string15_bettercap_offensive_tool_keyword = /\/wifi_hopping\./
                        $string16_bettercap_offensive_tool_keyword = /arp\.spoof\son/
                        $string17_bettercap_offensive_tool_keyword = /arp\.spoof\./
                        $string18_bettercap_offensive_tool_keyword = /arp\.spoof\.targets/
                        $string19_bettercap_offensive_tool_keyword = /arp_spoof\./
                        $string20_bettercap_offensive_tool_keyword = "ArpSpoofer"
                        $string21_bettercap_offensive_tool_keyword = "bettercap "
                        $string22_bettercap_offensive_tool_keyword = /bettercap\./
                        $string23_bettercap_offensive_tool_keyword = /bettercap_\.deb/
                        $string24_bettercap_offensive_tool_keyword = /bettercap\-master\.zip/
                        $string25_bettercap_offensive_tool_keyword = /ble_recon\.go/
                        $string26_bettercap_offensive_tool_keyword = /dhcp6\.spoof\./
                        $string27_bettercap_offensive_tool_keyword = /dns\.spoof\son/
                        $string28_bettercap_offensive_tool_keyword = /dns\.spoof\.address/
                        $string29_bettercap_offensive_tool_keyword = /dns\.spoof\.all/
                        $string30_bettercap_offensive_tool_keyword = /dns\.spoof\.domains/
                        $string31_bettercap_offensive_tool_keyword = /dns\.spoof\.hosts/
                        $string32_bettercap_offensive_tool_keyword = /dns_spoof\./
                        $string33_bettercap_offensive_tool_keyword = /mac\.changer\son/
                        $string34_bettercap_offensive_tool_keyword = /ndp_spoof\./
                        $string35_bettercap_offensive_tool_keyword = /net\.fuzz\s/
                        $string36_bettercap_offensive_tool_keyword = /net\.fuzz\./
                        $string37_bettercap_offensive_tool_keyword = /net\.probe\son/
                        $string38_bettercap_offensive_tool_keyword = /net\.probe\son/
                        $string39_bettercap_offensive_tool_keyword = /net\.sniff\s/
                        $string40_bettercap_offensive_tool_keyword = /net\.sniff\./
                        $string41_bettercap_offensive_tool_keyword = /net_recon\./
                        $string42_bettercap_offensive_tool_keyword = /wifi_fake_auth\./
                        $string43_bettercap_offensive_tool_keyword = "wifi_recon_handshakes"
                        $string44_bettercap_offensive_tool_keyword = /net\.recon\s/

    condition:
        any of them
}