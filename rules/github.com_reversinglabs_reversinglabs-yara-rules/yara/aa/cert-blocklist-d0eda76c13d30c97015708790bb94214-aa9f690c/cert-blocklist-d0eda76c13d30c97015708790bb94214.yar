import "pe"
rule cert_blocklist_d0eda76c13d30c97015708790bb94214 {
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
            pe.signatures[i].subject contains "LAEN ApS" and (
                pe.signatures[i].serial == "00:d0:ed:a7:6c:13:d3:0c:97:01:57:08:79:0b:b9:42:14" or
                pe.signatures[i].serial == "d0:ed:a7:6c:13:d3:0c:97:01:57:08:79:0b:b9:42:14"
            ) and
            1619136000 <= pe.signatures[i].not_after
        )
}