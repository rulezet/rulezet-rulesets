import "pe"
rule cert_blocklist_fd7b7a8678a67181a54bc7499eba44da {
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
            pe.signatures[i].subject contains "IMRAN IT SERVICES LTD" and (
                pe.signatures[i].serial == "00:fd:7b:7a:86:78:a6:71:81:a5:4b:c7:49:9e:ba:44:da" or
                pe.signatures[i].serial == "fd:7b:7a:86:78:a6:71:81:a5:4b:c7:49:9e:ba:44:da"
            ) and
            1548028800 <= pe.signatures[i].not_after
        )
}