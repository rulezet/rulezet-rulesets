import "pe"
rule cert_blocklist_0940fa9a4080f35052b2077333769c2f {
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
            pe.signatures[i].subject contains "PROFF LAIN, OOO" and
            pe.signatures[i].serial == "09:40:fa:9a:40:80:f3:50:52:b2:07:73:33:76:9c:2f" and
            1603497600 <= pe.signatures[i].not_after
        )
}