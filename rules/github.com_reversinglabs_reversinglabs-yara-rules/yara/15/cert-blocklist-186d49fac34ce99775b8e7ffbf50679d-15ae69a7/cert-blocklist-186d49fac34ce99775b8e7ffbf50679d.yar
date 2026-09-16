import "pe"
rule cert_blocklist_186d49fac34ce99775b8e7ffbf50679d {
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
            pe.signatures[i].subject contains "Hairis LLC" and
            pe.signatures[i].serial == "18:6d:49:fa:c3:4c:e9:97:75:b8:e7:ff:bf:50:67:9d" and
            1602234590 <= pe.signatures[i].not_after
        )
}