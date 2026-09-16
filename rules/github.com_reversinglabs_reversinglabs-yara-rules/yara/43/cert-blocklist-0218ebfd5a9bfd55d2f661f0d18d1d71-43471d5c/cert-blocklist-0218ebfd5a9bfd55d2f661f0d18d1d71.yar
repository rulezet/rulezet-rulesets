import "pe"
rule cert_blocklist_0218ebfd5a9bfd55d2f661f0d18d1d71 {
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
            pe.signatures[i].subject contains "REI LUX UK LIMITED" and
            pe.signatures[i].serial == "02:18:eb:fd:5a:9b:fd:55:d2:f6:61:f0:d1:8d:1d:71" and
            1608508800 <= pe.signatures[i].not_after
        )
}