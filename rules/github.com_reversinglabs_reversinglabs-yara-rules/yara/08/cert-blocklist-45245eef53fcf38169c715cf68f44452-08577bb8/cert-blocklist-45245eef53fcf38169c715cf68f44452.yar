import "pe"
rule cert_blocklist_45245eef53fcf38169c715cf68f44452 {
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
            pe.signatures[i].subject contains "PAPER AND CORE SUPPLIES LTD" and
            pe.signatures[i].serial == "45:24:5e:ef:53:fc:f3:81:69:c7:15:cf:68:f4:44:52" and
            1639958400 <= pe.signatures[i].not_after
        )
}