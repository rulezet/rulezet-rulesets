import "pe"
rule cert_blocklist_ac0a7b9420b369af3ddb748385b981 {
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
            pe.signatures[i].subject contains "OOO Tochka" and (
                pe.signatures[i].serial == "00:ac:0a:7b:94:20:b3:69:af:3d:db:74:83:85:b9:81" or
                pe.signatures[i].serial == "ac:0a:7b:94:20:b3:69:af:3d:db:74:83:85:b9:81"
            ) and
            1604620800 <= pe.signatures[i].not_after
        )
}