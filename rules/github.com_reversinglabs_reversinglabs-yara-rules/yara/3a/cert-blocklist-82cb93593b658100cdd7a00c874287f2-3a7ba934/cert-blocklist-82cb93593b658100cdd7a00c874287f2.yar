import "pe"
rule cert_blocklist_82cb93593b658100cdd7a00c874287f2 {
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
            pe.signatures[i].subject contains "Sportsonline24 B.V." and (
                pe.signatures[i].serial == "00:82:cb:93:59:3b:65:81:00:cd:d7:a0:0c:87:42:87:f2" or
                pe.signatures[i].serial == "82:cb:93:59:3b:65:81:00:cd:d7:a0:0c:87:42:87:f2"
            ) and
            1605117874 <= pe.signatures[i].not_after
        )
}