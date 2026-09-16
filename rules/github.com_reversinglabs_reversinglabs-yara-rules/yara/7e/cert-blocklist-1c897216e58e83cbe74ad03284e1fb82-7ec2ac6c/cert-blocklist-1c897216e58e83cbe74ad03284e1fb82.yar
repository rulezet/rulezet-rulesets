import "pe"
rule cert_blocklist_1c897216e58e83cbe74ad03284e1fb82 {
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
            pe.signatures[i].subject contains "M-Trans Maciej Caban" and
            pe.signatures[i].serial == "1c:89:72:16:e5:8e:83:cb:e7:4a:d0:32:84:e1:fb:82" and
            1639119705 <= pe.signatures[i].not_after
        )
}