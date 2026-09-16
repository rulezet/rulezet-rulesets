import "pe"
rule cert_blocklist_7b91468122273aa32b7cfc80c331ea13 {
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
            pe.signatures[i].subject contains "OOO KBI" and
            pe.signatures[i].serial == "7b:91:46:81:22:27:3a:a3:2b:7c:fc:80:c3:31:ea:13" and
            1586942863 <= pe.signatures[i].not_after
        )
}