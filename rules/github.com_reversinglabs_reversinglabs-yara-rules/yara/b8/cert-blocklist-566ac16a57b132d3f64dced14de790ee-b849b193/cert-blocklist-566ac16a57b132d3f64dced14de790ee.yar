import "pe"
rule cert_blocklist_566ac16a57b132d3f64dced14de790ee {
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
            pe.signatures[i].subject contains "Unirad LLC" and
            pe.signatures[i].serial == "56:6a:c1:6a:57:b1:32:d3:f6:4d:ce:d1:4d:e7:90:ee" and
            1562889600 <= pe.signatures[i].not_after
        )
}