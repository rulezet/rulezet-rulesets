import "pe"
rule cert_blocklist_2c84f9136059e96134f8766670eacd52 {
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
            pe.signatures[i].subject contains "Open Source Developer, DIEGO MANUEL RODRIGUEZ" and
            pe.signatures[i].serial == "2c:84:f9:13:60:59:e9:61:34:f8:76:66:70:ea:cd:52" and
            1442215311 <= pe.signatures[i].not_after
        )
}