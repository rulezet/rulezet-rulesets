import "pe"
rule cert_blocklist_21220646c639d62c16992f46 {
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
            pe.signatures[i].subject contains "Sivi Technology Limited" and
            pe.signatures[i].serial == "21:22:06:46:c6:39:d6:2c:16:99:2f:46" and
            1466130984 <= pe.signatures[i].not_after
        )
}