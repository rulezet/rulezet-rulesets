import "pe"
rule cert_blocklist_43db4448d870d7bdc275f36a01fba36f {
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
            pe.signatures[i].subject contains "3-T TOV" and
            pe.signatures[i].serial == "43:db:44:48:d8:70:d7:bd:c2:75:f3:6a:01:fb:a3:6f" and
            1436227199 <= pe.signatures[i].not_after
        )
}