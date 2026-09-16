import "pe"
rule cert_blocklist_2f4a25d52b16eb4c9dfe71ebbd8121bb {
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
            pe.signatures[i].subject contains "Blist LLC" and
            pe.signatures[i].serial == "2f:4a:25:d5:2b:16:eb:4c:9d:fe:71:eb:bd:81:21:bb" and
            1629763200 <= pe.signatures[i].not_after
        )
}