import "pe"
rule cert_blocklist_e7e7f7180666546ce7a8da32119f5ce1 {
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
            pe.signatures[i].subject contains "C\\xC3\\x94NG TY TNHH PDF SOFTWARE" and (
                pe.signatures[i].serial == "00:e7:e7:f7:18:06:66:54:6c:e7:a8:da:32:11:9f:5c:e1" or
                pe.signatures[i].serial == "e7:e7:f7:18:06:66:54:6c:e7:a8:da:32:11:9f:5c:e1"
            ) and
            1661558399 <= pe.signatures[i].not_after
        )
}