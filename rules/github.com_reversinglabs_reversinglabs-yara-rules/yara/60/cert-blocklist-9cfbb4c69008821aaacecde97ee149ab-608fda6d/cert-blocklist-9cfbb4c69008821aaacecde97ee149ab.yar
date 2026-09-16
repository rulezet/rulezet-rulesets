import "pe"
rule cert_blocklist_9cfbb4c69008821aaacecde97ee149ab {
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
            pe.signatures[i].subject contains "Kivaliz Prest s.r.l." and (
                pe.signatures[i].serial == "00:9c:fb:b4:c6:90:08:82:1a:aa:ce:cd:e9:7e:e1:49:ab" or
                pe.signatures[i].serial == "9c:fb:b4:c6:90:08:82:1a:aa:ce:cd:e9:7e:e1:49:ab"
            ) and
            1592363914 <= pe.signatures[i].not_after
        )
}