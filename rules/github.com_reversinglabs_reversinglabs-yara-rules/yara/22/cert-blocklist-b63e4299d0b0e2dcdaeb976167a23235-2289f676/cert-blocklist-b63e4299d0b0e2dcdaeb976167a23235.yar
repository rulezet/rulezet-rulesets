import "pe"
rule cert_blocklist_b63e4299d0b0e2dcdaeb976167a23235 {
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
            pe.signatures[i].subject contains "Baltservis LLC" and (
                pe.signatures[i].serial == "00:b6:3e:42:99:d0:b0:e2:dc:da:eb:97:61:67:a2:32:35" or
                pe.signatures[i].serial == "b6:3e:42:99:d0:b0:e2:dc:da:eb:97:61:67:a2:32:35"
            ) and
            1604102400 <= pe.signatures[i].not_after
        )
}