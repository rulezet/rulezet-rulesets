import "pe"
rule cert_blocklist_6e32531ae83992f0573120a5e78de271 {
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
            pe.signatures[i].subject contains "3 AM CHP" and
            pe.signatures[i].serial == "6e:32:53:1a:e8:39:92:f0:57:31:20:a5:e7:8d:e2:71" and
            1451606399 <= pe.signatures[i].not_after
        )
}