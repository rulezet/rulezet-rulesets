import "pe"
rule cert_blocklist_56fff139df5ae7e788e5d72196dd563a {
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
            pe.signatures[i].subject contains "Cifromatika LLC" and
            pe.signatures[i].serial == "56:ff:f1:39:df:5a:e7:e7:88:e5:d7:21:96:dd:56:3a" and
            1606435200 <= pe.signatures[i].not_after
        )
}