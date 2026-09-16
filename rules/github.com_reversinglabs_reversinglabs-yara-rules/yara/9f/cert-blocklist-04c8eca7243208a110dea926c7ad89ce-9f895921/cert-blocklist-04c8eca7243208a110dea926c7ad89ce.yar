import "pe"
rule cert_blocklist_04c8eca7243208a110dea926c7ad89ce {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing GovRAT malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Open Source Developer, SINGH ADITYA" and
            pe.signatures[i].serial == "04:c8:ec:a7:24:32:08:a1:10:de:a9:26:c7:ad:89:ce" and
            1404172799 <= pe.signatures[i].not_after
        )
}