import "pe"
rule cert_blocklist_1249aa2ada4967969b71ce63bf187c38 {
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
            pe.signatures[i].subject contains "Umbrella LLC" and
            pe.signatures[i].serial == "12:49:aa:2a:da:49:67:96:9b:71:ce:63:bf:18:7c:38" and
            1599181200 <= pe.signatures[i].not_after
        )
}