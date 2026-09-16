import "pe"
rule cert_blocklist_01a90094c83412c00cf98dd2eb0d7042 {
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
            pe.signatures[i].subject contains "FreeVox SA" and
            pe.signatures[i].serial == "01:a9:00:94:c8:34:12:c0:0c:f9:8d:d2:eb:0d:70:42" and
            1376956799 <= pe.signatures[i].not_after
        )
}