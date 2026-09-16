import "pe"
rule cert_blocklist_d338f8a490e37e6c2be80a0e349929fa {
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
            pe.signatures[i].subject contains "SAGUARO ApS" and (
                pe.signatures[i].serial == "00:d3:38:f8:a4:90:e3:7e:6c:2b:e8:0a:0e:34:99:29:fa" or
                pe.signatures[i].serial == "d3:38:f8:a4:90:e3:7e:6c:2b:e8:0a:0e:34:99:29:fa"
            ) and
            1607558400 <= pe.signatures[i].not_after
        )
}