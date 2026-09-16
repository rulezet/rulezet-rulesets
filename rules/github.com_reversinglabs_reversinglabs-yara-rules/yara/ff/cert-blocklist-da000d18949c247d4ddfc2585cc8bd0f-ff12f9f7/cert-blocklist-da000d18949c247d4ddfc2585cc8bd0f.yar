import "pe"
rule cert_blocklist_da000d18949c247d4ddfc2585cc8bd0f {
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
            pe.signatures[i].subject contains "PORT-SERVIS LTD" and (
                pe.signatures[i].serial == "00:da:00:0d:18:94:9c:24:7d:4d:df:c2:58:5c:c8:bd:0f" or
                pe.signatures[i].serial == "da:00:0d:18:94:9c:24:7d:4d:df:c2:58:5c:c8:bd:0f"
            ) and
            1564444800 <= pe.signatures[i].not_after
        )
}