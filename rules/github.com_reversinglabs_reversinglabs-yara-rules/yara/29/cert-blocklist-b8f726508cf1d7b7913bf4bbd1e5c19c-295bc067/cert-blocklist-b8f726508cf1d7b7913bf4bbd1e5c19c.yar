import "pe"
rule cert_blocklist_b8f726508cf1d7b7913bf4bbd1e5c19c {
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
            pe.signatures[i].subject contains "Merkuri LLC" and (
                pe.signatures[i].serial == "00:b8:f7:26:50:8c:f1:d7:b7:91:3b:f4:bb:d1:e5:c1:9c" or
                pe.signatures[i].serial == "b8:f7:26:50:8c:f1:d7:b7:91:3b:f4:bb:d1:e5:c1:9c"
            ) and
            1619568000 <= pe.signatures[i].not_after
        )
}