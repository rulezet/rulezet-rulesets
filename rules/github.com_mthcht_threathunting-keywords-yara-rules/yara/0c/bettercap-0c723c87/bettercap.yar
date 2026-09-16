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
                        $string2 = /\s\-caplet\s.{0,100}\.cap/
                        $string3 = /\s\-eval\s.{0,100}caplets\.update.{0,100}\sui\.update/
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
                        $string14 = /\/net_sniff_.{0,100}\./
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