import "pe"
rule cert_blocklist_8f4c49dae1f1ff0ebe9104c6f73242bd {
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
            pe.signatures[i].subject contains "Contact Merger Holding ApS" and (
                pe.signatures[i].serial == "00:8f:4c:49:da:e1:f1:ff:0e:be:91:04:c6:f7:32:42:bd" or
                pe.signatures[i].serial == "8f:4c:49:da:e1:f1:ff:0e:be:91:04:c6:f7:32:42:bd"
            ) and
            1636039748 <= pe.signatures[i].not_after
        )
}