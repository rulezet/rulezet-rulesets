import "pe"
rule cert_blocklist_2880a7f7ff2d334aa08744a8754fab2c {
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
            pe.signatures[i].subject contains "Garena Online Pte Ltd" and
            pe.signatures[i].serial == "28:80:a7:f7:ff:2d:33:4a:a0:87:44:a8:75:4f:ab:2c" and
            1393891199 <= pe.signatures[i].not_after
        )
}