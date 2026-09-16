import "pe"
rule cert_blocklist_262ca7ae19d688138e75932832b18f9d {
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
            pe.signatures[i].subject contains "Bisoyetutu Ltd Ltd" and
            pe.signatures[i].serial == "26:2c:a7:ae:19:d6:88:13:8e:75:93:28:32:b1:8f:9d" and
            1616025600 <= pe.signatures[i].not_after
        )
}