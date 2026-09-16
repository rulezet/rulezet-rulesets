import "pe"
rule cert_blocklist_c96086f1894e6420d2b4bdeea834c4d7 {
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
            pe.signatures[i].subject contains "THE FAITH SP Z O O" and (
                pe.signatures[i].serial == "00:c9:60:86:f1:89:4e:64:20:d2:b4:bd:ee:a8:34:c4:d7" or
                pe.signatures[i].serial == "c9:60:86:f1:89:4e:64:20:d2:b4:bd:ee:a8:34:c4:d7"
            ) and
            1644969600 <= pe.signatures[i].not_after
        )
}