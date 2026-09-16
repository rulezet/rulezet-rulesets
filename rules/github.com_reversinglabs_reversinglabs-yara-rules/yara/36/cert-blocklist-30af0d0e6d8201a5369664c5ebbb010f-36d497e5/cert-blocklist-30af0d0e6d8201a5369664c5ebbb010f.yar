import "pe"
rule cert_blocklist_30af0d0e6d8201a5369664c5ebbb010f {
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
            pe.signatures[i].subject contains "3N-\\xC5\\xA0PORT podjetje za in\\xC5\\xBEeniring, storitve in trgovino d.o.o." and
            pe.signatures[i].serial == "30:af:0d:0e:6d:82:01:a5:36:96:64:c5:eb:bb:01:0f" and
            1613433600 <= pe.signatures[i].not_after
        )
}