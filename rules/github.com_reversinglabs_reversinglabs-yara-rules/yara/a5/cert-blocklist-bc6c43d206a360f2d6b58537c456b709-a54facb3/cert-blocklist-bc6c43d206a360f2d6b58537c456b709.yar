import "pe"
rule cert_blocklist_bc6c43d206a360f2d6b58537c456b709 {
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
            pe.signatures[i].subject contains "ANKADA GROUP, d.o.o." and (
                pe.signatures[i].serial == "00:bc:6c:43:d2:06:a3:60:f2:d6:b5:85:37:c4:56:b7:09" or
                pe.signatures[i].serial == "bc:6c:43:d2:06:a3:60:f2:d6:b5:85:37:c4:56:b7:09"
            ) and
            1616630400 <= pe.signatures[i].not_after
        )
}