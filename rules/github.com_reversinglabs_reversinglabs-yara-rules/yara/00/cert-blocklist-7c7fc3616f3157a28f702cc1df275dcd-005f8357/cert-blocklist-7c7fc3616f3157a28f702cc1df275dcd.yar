import "pe"
rule cert_blocklist_7c7fc3616f3157a28f702cc1df275dcd {
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
            pe.signatures[i].subject contains "CFES Projects Ltd" and
            pe.signatures[i].serial == "7c:7f:c3:61:6f:31:57:a2:8f:70:2c:c1:df:27:5d:cd" and
            1522972800 <= pe.signatures[i].not_after
        )
}