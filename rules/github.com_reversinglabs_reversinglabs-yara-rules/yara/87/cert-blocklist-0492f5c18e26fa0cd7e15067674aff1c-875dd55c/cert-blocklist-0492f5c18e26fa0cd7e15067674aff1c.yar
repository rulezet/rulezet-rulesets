import "pe"
rule cert_blocklist_0492f5c18e26fa0cd7e15067674aff1c {
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
            pe.signatures[i].subject contains "Ghada Saffarini" and
            pe.signatures[i].serial == "04:92:f5:c1:8e:26:fa:0c:d7:e1:50:67:67:4a:ff:1c" and
            1445990399 <= pe.signatures[i].not_after
        )
}