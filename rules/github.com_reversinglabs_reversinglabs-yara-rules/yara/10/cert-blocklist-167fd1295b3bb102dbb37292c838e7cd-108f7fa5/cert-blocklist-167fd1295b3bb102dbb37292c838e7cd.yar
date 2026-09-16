import "pe"
rule cert_blocklist_167fd1295b3bb102dbb37292c838e7cd {
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
            pe.signatures[i].subject contains "Yu Bao" and
            pe.signatures[i].serial == "16:7f:d1:29:5b:3b:b1:02:db:b3:72:92:c8:38:e7:cd" and
            1476921600 <= pe.signatures[i].not_after
        )
}