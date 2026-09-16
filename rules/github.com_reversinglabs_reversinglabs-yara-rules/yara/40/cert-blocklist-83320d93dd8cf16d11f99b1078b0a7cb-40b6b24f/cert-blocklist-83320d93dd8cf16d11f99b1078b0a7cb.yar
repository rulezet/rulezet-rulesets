import "pe"
rule cert_blocklist_83320d93dd8cf16d11f99b1078b0a7cb {
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
            pe.signatures[i].subject contains "TRANS LTD" and (
                pe.signatures[i].serial == "00:83:32:0d:93:dd:8c:f1:6d:11:f9:9b:10:78:b0:a7:cb" or
                pe.signatures[i].serial == "83:32:0d:93:dd:8c:f1:6d:11:f9:9b:10:78:b0:a7:cb"
            ) and
            1524614400 <= pe.signatures[i].not_after
        )
}