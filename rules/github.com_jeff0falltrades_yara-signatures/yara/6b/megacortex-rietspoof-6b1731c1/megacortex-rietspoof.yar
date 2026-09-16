import "pe"
rule megacortex_rietspoof {
    meta:
        author = "jeFF0Falltrades"

    strings:
        $cert = "8 Quarles Park Road1"
    
    condition:
         uint16(0) == 0x5a4d and ($cert or (for any i in (0..pe.number_of_signatures) : (pe.signatures[i].serial == "53:CC:4C:69:E5:6A:7D:BC:36:67:D5:FF:D5:24:AA:4B" or pe.signatures[i].serial == "1D:A2:48:30:6F:9B:26:18:D0:82:E0:96:7D:33:D3:6A" or pe.signatures[i].serial == "13:EA:28:70:5B:F4:EC:ED:0C:36:63:09:80:61:43:36" or pe.signatures[i].serial == "0E:CF:F4:38:C8:FE:BF:35:6E:04:D8:6A:98:1B:1A:50" or pe.signatures[i].serial == "7E:93:EB:FB:7C:C6:4E:59:EA:4B:9A:77:D4:06:FC:3B" or pe.signatures[i].serial == "00:AD:72:9A:65:F1:78:47:AC:B8:F8:49:6A:76:80:FF:1E" or pe.signatures[i].serial == "01:FD:6D:30:FC:A3:CA:51:A8:1B:BC:64:0E:35:03:2D")))
}