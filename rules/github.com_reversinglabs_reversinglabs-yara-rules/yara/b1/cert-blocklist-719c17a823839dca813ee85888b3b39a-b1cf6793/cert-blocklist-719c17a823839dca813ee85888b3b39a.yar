import "pe"
rule cert_blocklist_719c17a823839dca813ee85888b3b39a {
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
            pe.signatures[i].subject contains "Yuanyuan Zhang" and
            pe.signatures[i].serial == "71:9c:17:a8:23:83:9d:ca:81:3e:e8:58:88:b3:b3:9a" and
            1479686400 <= pe.signatures[i].not_after
        )
}