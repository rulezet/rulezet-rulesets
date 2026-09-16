import "pe"
rule cert_blocklist_9bd81a9adaf71f1ff081c1f4a05d7fd7 {
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
            pe.signatures[i].subject contains "SMART TOYS AND GAMES, INC" and (
                pe.signatures[i].serial == "00:9b:d8:1a:9a:da:f7:1f:1f:f0:81:c1:f4:a0:5d:7f:d7" or
                pe.signatures[i].serial == "9b:d8:1a:9a:da:f7:1f:1f:f0:81:c1:f4:a0:5d:7f:d7"
            ) and
            1601683200 <= pe.signatures[i].not_after
        )
}