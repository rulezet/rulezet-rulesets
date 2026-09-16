import "pe"
rule cert_blocklist_0a7be7722b65a866ebcd3bd7f8f10825 {
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
            pe.signatures[i].subject contains "Rebound Infotech Limited" and
            pe.signatures[i].serial == "0a:7b:e7:72:2b:65:a8:66:eb:cd:3b:d7:f8:f1:08:25" and
            1637971200 <= pe.signatures[i].not_after
        )
}