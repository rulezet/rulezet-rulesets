import "pe"
rule cert_blocklist_734819463c1195bd6e135ce4d5bf49bc {
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
            pe.signatures[i].subject contains "videoalarm s. r. o." and
            pe.signatures[i].serial == "73:48:19:46:3c:11:95:bd:6e:13:5c:e4:d5:bf:49:bc" and
            1637884800 <= pe.signatures[i].not_after
        )
}