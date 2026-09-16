import "pe"
rule cert_blocklist_b72179c027b9037ee220e81ab18fe56d {
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
            pe.signatures[i].subject contains "Planeta, TOV" and (
                pe.signatures[i].serial == "00:b7:21:79:c0:27:b9:03:7e:e2:20:e8:1a:b1:8f:e5:6d" or
                pe.signatures[i].serial == "b7:21:79:c0:27:b9:03:7e:e2:20:e8:1a:b1:8f:e5:6d"
            ) and
            1603381300 <= pe.signatures[i].not_after
        )
}