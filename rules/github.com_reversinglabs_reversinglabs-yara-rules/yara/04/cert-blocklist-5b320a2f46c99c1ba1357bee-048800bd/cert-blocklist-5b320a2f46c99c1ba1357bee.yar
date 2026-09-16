import "pe"
rule cert_blocklist_5b320a2f46c99c1ba1357bee {
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
            pe.signatures[i].subject contains "REGION TOURISM LLC" and
            pe.signatures[i].serial == "5b:32:0a:2f:46:c9:9c:1b:a1:35:7b:ee" and
            1602513116 <= pe.signatures[i].not_after
        )
}