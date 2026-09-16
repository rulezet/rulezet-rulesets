import "pe"
rule cert_blocklist_bc32bbe5bbb4f06f490c50651cd5da50 {
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
            pe.signatures[i].subject contains "Remedica Medical Education and Publishing Ltd" and (
                pe.signatures[i].serial == "00:bc:32:bb:e5:bb:b4:f0:6f:49:0c:50:65:1c:d5:da:50" or
                pe.signatures[i].serial == "bc:32:bb:e5:bb:b4:f0:6f:49:0c:50:65:1c:d5:da:50"
            ) and
            1387151999 <= pe.signatures[i].not_after
        )
}