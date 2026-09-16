import "pe"
rule megacortex_meterpreter {
    meta:
        author = "jeFF0Falltrades"

    strings:
        $cert = "Bud. 120-A, Vul. Balkivska1"

    condition:
        uint16(0) == 0x5a4d and $cert and (for any i in (0..pe.number_of_signatures) : (pe.signatures[i].serial == "00:CA:0E:70:90:D4:82:70:04:C9:9A:F2:FC:7D:73:3C:02" or pe.signatures[i].serial == "1D:A2:48:30:6F:9B:26:18:D0:82:E0:96:7D:33:D3:6A" or pe.signatures[i].serial == "01:FD:6D:30:FC:A3:CA:51:A8:1B:BC:64:0E:35:03:2D" or pe.signatures[i].serial == "03:01:9A:02:3A:FF:58:B1:6B:D6:D5:EA:E6:17:F0:66" or pe.signatures[i].serial == "06:FD:F9:03:96:03:AD:EA:00:0A:EB:3F:27:BB:BA:1B" or pe.signatures[i].serial == "0C:E7:E0:E5:17:D8:46:FE:8F:E5:60:FC:1B:F0:30:39"))
}