import "pe"
rule cert_blocklist_fd8c468cc1b45c9cfb41cbd8c835cc9e {
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
            pe.signatures[i].subject contains "Pivo ZLoun s.r.o." and (
                pe.signatures[i].serial == "00:fd:8c:46:8c:c1:b4:5c:9c:fb:41:cb:d8:c8:35:cc:9e" or
                pe.signatures[i].serial == "fd:8c:46:8c:c1:b4:5c:9c:fb:41:cb:d8:c8:35:cc:9e"
            ) and
            1604019600 <= pe.signatures[i].not_after
        )
}