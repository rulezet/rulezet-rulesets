import "pe"
rule cert_blocklist_addbec454b5479cabd940a72df4500af {
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
            pe.signatures[i].subject contains "SHAT LIMITED" and (
                pe.signatures[i].serial == "00:ad:db:ec:45:4b:54:79:ca:bd:94:0a:72:df:45:00:af" or
                pe.signatures[i].serial == "ad:db:ec:45:4b:54:79:ca:bd:94:0a:72:df:45:00:af"
            ) and
            1612828800 <= pe.signatures[i].not_after
        )
}