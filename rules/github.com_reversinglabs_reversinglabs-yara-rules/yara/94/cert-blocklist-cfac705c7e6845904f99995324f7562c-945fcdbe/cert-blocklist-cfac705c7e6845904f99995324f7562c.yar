import "pe"
rule cert_blocklist_cfac705c7e6845904f99995324f7562c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "HMWOCFPSDLAFMFZIVD" and (
                pe.signatures[i].serial == "cf:ac:70:5c:7e:68:45:90:4f:99:99:53:24:f7:56:2c" or
                pe.signatures[i].serial == "30:53:8f:a3:81:97:ba:6f:b0:66:66:ac:db:08:a9:d4"
            ) and
            1601918720 <= pe.signatures[i].not_after
        )
}