import "pe"
rule cert_blocklist_07bb6a9d1c642c5973c16d5353b17ca4 {
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
            pe.signatures[i].subject contains "MADAS d.o.o." and
            pe.signatures[i].serial == "07:bb:6a:9d:1c:64:2c:59:73:c1:6d:53:53:b1:7c:a4" and
            1601856001 <= pe.signatures[i].not_after
        )
}