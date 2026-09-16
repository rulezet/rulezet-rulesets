import "pe"
rule cert_blocklist_13c8351aece71c731158980f575f4133 {
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
            pe.signatures[i].subject contains "Opera Software ASA" and
            pe.signatures[i].serial == "13:c8:35:1a:ec:e7:1c:73:11:58:98:0f:57:5f:41:33" and
            1371513600 <= pe.signatures[i].not_after
        )
}