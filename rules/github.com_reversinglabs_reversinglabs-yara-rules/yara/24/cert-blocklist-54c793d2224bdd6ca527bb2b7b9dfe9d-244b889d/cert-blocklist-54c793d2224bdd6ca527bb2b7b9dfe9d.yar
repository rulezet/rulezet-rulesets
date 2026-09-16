import "pe"
rule cert_blocklist_54c793d2224bdd6ca527bb2b7b9dfe9d {
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
            pe.signatures[i].subject contains "CODE - HANDLE, s. r. o." and
            pe.signatures[i].serial == "54:c7:93:d2:22:4b:dd:6c:a5:27:bb:2b:7b:9d:fe:9d" and
            1629676800 <= pe.signatures[i].not_after
        )
}