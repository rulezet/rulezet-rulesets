import "pe"
rule cert_blocklist_45eb9187a2505d8e6c842e6d366ad0c8 {
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
            pe.signatures[i].subject contains "BAKERA s.r.o." and
            pe.signatures[i].serial == "45:eb:91:87:a2:50:5d:8e:6c:84:2e:6d:36:6a:d0:c8" and
            1607040000 <= pe.signatures[i].not_after
        )
}