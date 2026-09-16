import "pe"
rule cert_blocklist_08d4dc90047b8470ccaf3924dfbd8b5f {
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
            pe.signatures[i].subject contains "OOO Dibies" and
            pe.signatures[i].serial == "08:d4:dc:90:04:7b:84:70:cc:af:39:24:df:bd:8b:5f" and
            1619136000 <= pe.signatures[i].not_after
        )
}