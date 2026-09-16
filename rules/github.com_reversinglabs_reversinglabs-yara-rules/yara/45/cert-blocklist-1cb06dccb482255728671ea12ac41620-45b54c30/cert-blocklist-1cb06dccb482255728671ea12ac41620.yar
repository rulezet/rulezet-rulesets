import "pe"
rule cert_blocklist_1cb06dccb482255728671ea12ac41620 {
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
            pe.signatures[i].subject contains "Fangzhen Li" and
            pe.signatures[i].serial == "1c:b0:6d:cc:b4:82:25:57:28:67:1e:a1:2a:c4:16:20" and
            1445126399 <= pe.signatures[i].not_after
        )
}