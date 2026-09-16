import "pe"
rule cert_blocklist_08d4352185317271c1cec9d05c279af7 {
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
            pe.signatures[i].subject contains "Retalit LLC" and
            pe.signatures[i].serial == "08:d4:35:21:85:31:72:71:c1:ce:c9:d0:5c:27:9a:f7" and
            1596585601 <= pe.signatures[i].not_after
        )
}