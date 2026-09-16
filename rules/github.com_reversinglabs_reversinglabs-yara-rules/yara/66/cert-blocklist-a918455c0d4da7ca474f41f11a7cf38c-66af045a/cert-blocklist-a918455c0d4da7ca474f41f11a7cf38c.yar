import "pe"
rule cert_blocklist_a918455c0d4da7ca474f41f11a7cf38c {
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
            pe.signatures[i].subject contains "MIDDRA INTERNATIONAL CORP." and (
                pe.signatures[i].serial == "00:a9:18:45:5c:0d:4d:a7:ca:47:4f:41:f1:1a:7c:f3:8c" or
                pe.signatures[i].serial == "a9:18:45:5c:0d:4d:a7:ca:47:4f:41:f1:1a:7c:f3:8c"
            ) and
            1618963200 <= pe.signatures[i].not_after
        )
}