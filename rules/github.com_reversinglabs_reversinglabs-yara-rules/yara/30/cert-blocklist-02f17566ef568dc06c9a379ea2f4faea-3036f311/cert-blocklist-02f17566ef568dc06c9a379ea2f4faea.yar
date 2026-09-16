import "pe"
rule cert_blocklist_02f17566ef568dc06c9a379ea2f4faea {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VALERIANO BEDESCHI" and
            pe.signatures[i].serial == "02:f1:75:66:ef:56:8d:c0:6c:9a:37:9e:a2:f4:fa:ea" and
            1441324799 <= pe.signatures[i].not_after
        )
}