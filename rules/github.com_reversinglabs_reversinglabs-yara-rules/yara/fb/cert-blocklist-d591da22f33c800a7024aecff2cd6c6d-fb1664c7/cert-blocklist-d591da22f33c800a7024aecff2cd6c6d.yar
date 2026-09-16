import "pe"
rule cert_blocklist_d591da22f33c800a7024aecff2cd6c6d {
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
            pe.signatures[i].subject contains "OOO T2 Soft" and (
                pe.signatures[i].serial == "00:d5:91:da:22:f3:3c:80:0a:70:24:ae:cf:f2:cd:6c:6d" or
                pe.signatures[i].serial == "d5:91:da:22:f3:3c:80:0a:70:24:ae:cf:f2:cd:6c:6d"
            ) and
            1588679107 <= pe.signatures[i].not_after
        )
}