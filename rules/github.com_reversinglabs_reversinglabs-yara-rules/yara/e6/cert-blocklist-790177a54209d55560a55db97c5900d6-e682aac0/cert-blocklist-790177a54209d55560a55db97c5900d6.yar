import "pe"
rule cert_blocklist_790177a54209d55560a55db97c5900d6 {
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
            pe.signatures[i].subject contains "MAK GmbH" and
            pe.signatures[i].serial == "79:01:77:a5:42:09:d5:55:60:a5:5d:b9:7c:59:00:d6" and
            1594080000 <= pe.signatures[i].not_after
        )
}