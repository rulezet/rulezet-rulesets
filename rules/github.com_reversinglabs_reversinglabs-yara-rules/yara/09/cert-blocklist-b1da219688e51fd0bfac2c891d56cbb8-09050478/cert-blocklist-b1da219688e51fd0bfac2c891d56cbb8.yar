import "pe"
rule cert_blocklist_b1da219688e51fd0bfac2c891d56cbb8 {
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
            pe.signatures[i].subject contains "FIRNEEZ EUROPE LIMITED" and (
                pe.signatures[i].serial == "00:b1:da:21:96:88:e5:1f:d0:bf:ac:2c:89:1d:56:cb:b8" or
                pe.signatures[i].serial == "b1:da:21:96:88:e5:1f:d0:bf:ac:2c:89:1d:56:cb:b8"
            ) and
            1542931200 <= pe.signatures[i].not_after
        )
}