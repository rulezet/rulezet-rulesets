import "pe"
rule cert_blocklist_5333d3079d8afda715703775e1389991 {
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
            pe.signatures[i].subject contains "Trambambon LLC" and
            pe.signatures[i].serial == "53:33:d3:07:9d:8a:fd:a7:15:70:37:75:e1:38:99:91" and
            1239148800 <= pe.signatures[i].not_after
        )
}